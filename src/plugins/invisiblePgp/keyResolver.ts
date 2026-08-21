/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import * as DataStore from "@api/DataStore";

import { StoredKey } from "./types";

/**
 * Resolves the public key a signature was made with.
 *
 * Order: local keyring (DataStore) -> WKD (advertised uid) -> Keyoxide -> keys.openpgp.org.
 * Network lookups are opt-out and rate-limited by a negative cache, so a channel full of unsigned
 * or unknown-key messages never turns into a request storm.
 */

const STORE_KEY = "InvisiblePGP_keyring";

const NEGATIVE_TTL_MS = 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 8000;

/** keyId (16 hex, uppercase) -> stored key. Mirrors DataStore, loaded once at plugin start. */
let keyring: Record<string, StoredKey> = {};
let loaded = false;

/** keyId -> epoch millis of the last failed lookup. */
const negativeCache = new Map<string, number>();
/** Deduplicates concurrent lookups for the same key across a burst of messages. */
const inflight = new Map<string, Promise<StoredKey | null>>();

export interface ResolverOptions {
    allowNetwork: boolean;
    ttlDays: number;
}

export async function loadKeyring(): Promise<void> {
    if (loaded) return;
    keyring = (await DataStore.get<Record<string, StoredKey>>(STORE_KEY)) ?? {};
    loaded = true;
}

export function getKeyring(): Record<string, StoredKey> {
    return keyring;
}

async function persist(): Promise<void> {
    await DataStore.set(STORE_KEY, keyring);
}

export async function storeKey(key: StoredKey): Promise<void> {
    await loadKeyring();
    keyring[key.fingerprint.slice(-16).toUpperCase()] = key;
    negativeCache.delete(key.fingerprint.slice(-16).toUpperCase());
    await persist();
}

export async function removeKey(keyId: string): Promise<void> {
    await loadKeyring();
    delete keyring[keyId.toUpperCase()];
    await persist();
}

function isFresh(key: StoredKey, ttlDays: number): boolean {
    if (key.manual) return true; // hand-imported keys are the user's own trust decision
    return Date.now() - key.fetchedAt < ttlDays * 24 * 60 * 60 * 1000;
}

/**
 * @param keyId 16 hex chars from the message payload.
 * @param hintUid optional uid (usually an email) used for the WKD lookup.
 * @returns the armored public key, or null when nothing could be resolved.
 */
export async function resolvePublicKey(
    keyId: string,
    hintUid: string | undefined,
    opts: ResolverOptions
): Promise<StoredKey | null> {
    const id = keyId.toUpperCase();
    await loadKeyring();

    const cached = keyring[id];
    if (cached && isFresh(cached, opts.ttlDays)) return cached;

    if (!opts.allowNetwork) return cached ?? null;

    const failedAt = negativeCache.get(id);
    if (failedAt && Date.now() - failedAt < NEGATIVE_TTL_MS) return cached ?? null;

    const existing = inflight.get(id);
    if (existing) return existing;

    const task = lookupOnline(id, hintUid)
        .then(async found => {
            if (!found) {
                negativeCache.set(id, Date.now());
                return cached ?? null; // a stale key still beats no key at all
            }
            await storeKey(found);
            return found;
        })
        .catch(() => {
            negativeCache.set(id, Date.now());
            return cached ?? null;
        })
        .finally(() => inflight.delete(id));

    inflight.set(id, task);
    return task;
}

async function lookupOnline(keyId: string, hintUid?: string): Promise<StoredKey | null> {
    const email = extractEmail(hintUid);

    for (const url of candidateUrls(keyId, email)) {
        const armored = await tryFetchKey(url);
        if (armored) {
            return {
                armored,
                uid: hintUid ?? "",
                fingerprint: keyId, // refined by verify.ts once openpgp.js parses the key
                fetchedAt: Date.now(),
                manual: false
            };
        }
    }
    return null;
}

function* candidateUrls(keyId: string, email: string | null): Generator<string> {
    if (email) {
        const [local, domain] = email.split("@");
        // WKD advanced method first, then the direct method.
        yield wkdUrl(domain, local, true);
        yield wkdUrl(domain, local, false);
        // Keyoxide's WKD proxy — best effort, it also covers domains that block CORS directly.
        yield `https://keyoxide.org/proxy/wkd/${encodeURIComponent(email)}`;
    }
    yield `https://keys.openpgp.org/vks/v1/by-keyid/${keyId}`;
    if (email) yield `https://keys.openpgp.org/vks/v1/by-email/${encodeURIComponent(email)}`;
    yield `https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x${keyId}`;
}

/** Placeholder until the async hash resolves — see resolveWkdUrls. */
function wkdUrl(domain: string, local: string, advanced: boolean): string {
    const host = advanced ? `openpgpkey.${domain}` : domain;
    const path = advanced ? `/.well-known/openpgpkey/${domain}/hu/` : "/.well-known/openpgpkey/hu/";
    // The hashed local part is filled in by tryFetchKey via the {HU} marker so hashing stays async.
    return `https://${host}${path}{HU:${local}}?l=${encodeURIComponent(local)}`;
}

async function tryFetchKey(url: string): Promise<string | null> {
    const resolved = await expandHuMarker(url);
    if (!resolved) return null;

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    try {
        const res = await fetch(resolved, { signal: ctrl.signal, redirect: "follow" });
        if (!res.ok) return null;

        const buf = new Uint8Array(await res.arrayBuffer());
        if (buf.length === 0) return null;

        const text = new TextDecoder().decode(buf);
        if (text.includes("BEGIN PGP PUBLIC KEY BLOCK")) return text;

        // WKD serves raw binary keys; wrap them so openpgp.js can read them uniformly.
        return armor(buf);
    } catch {
        return null;
    } finally {
        clearTimeout(timer);
    }
}

/** Replaces a `{HU:localpart}` marker with its z-base-32(sha1(lowercased localpart)) form. */
async function expandHuMarker(url: string): Promise<string | null> {
    const m = url.match(/\{HU:([^}]*)\}/);
    if (!m) return url;
    try {
        return url.replace(m[0], await zbase32Sha1(m[1].toLowerCase()));
    } catch {
        return null;
    }
}

const ZBASE32 = "ybndrfg8ejkmcpqxot1uwisza345h769";

async function zbase32Sha1(input: string): Promise<string> {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-1", new TextEncoder().encode(input)));

    let out = "";
    let buffer = 0;
    let bits = 0;
    for (const byte of digest) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            out += ZBASE32[(buffer >> (bits - 5)) & 0b11111];
            bits -= 5;
        }
    }
    if (bits > 0) out += ZBASE32[(buffer << (5 - bits)) & 0b11111];

    return out;
}

/** RFC 4880 radix-64 wrapper, CRC24 checksum included — openpgp.js rejects armor without it. */
function armor(bytes: Uint8Array): string {
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);

    const b64 = btoa(bin).replace(/(.{64})/g, "$1\n");
    const checksum = btoa(String.fromCharCode(...crc24(bytes)));

    return `-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n${b64}\n=${checksum}\n-----END PGP PUBLIC KEY BLOCK-----\n`;
}

function crc24(bytes: Uint8Array): [number, number, number] {
    let crc = 0xb704ce;
    for (const byte of bytes) {
        crc ^= byte << 16;
        for (let i = 0; i < 8; i++) {
            crc <<= 1;
            if (crc & 0x1000000) crc ^= 0x1864cfb;
        }
    }
    crc &= 0xffffff;
    return [(crc >> 16) & 0xff, (crc >> 8) & 0xff, crc & 0xff];
}

function extractEmail(uid?: string): string | null {
    if (!uid) return null;
    const m = uid.match(/[\w.+-]+@[\w-]+\.[\w.-]+/);
    return m ? m[0].toLowerCase() : null;
}
