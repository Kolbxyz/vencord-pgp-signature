/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { canonicalSignedText, isUsableContext, MessageContext } from "./binding";
import { decodeZeroWidthToSignature } from "./zeroWidth";
import { resolvePublicKey, ResolverOptions } from "./keyResolver";
import { getTrustedSigner, recordVerified } from "./trustedSigners";
import { VerifyState, VerifyStatus } from "./types";

/**
 * Inbound verification, entirely in the renderer via openpgp.js.
 *
 * Nothing here ever runs synchronously during React render: components read the cache, and a miss
 * schedules a check whose result is published through a subscription.
 */

type OpenPGP = typeof import("openpgp");

let openpgpPromise: Promise<OpenPGP> | null = null;

/** openpgp.js is ~300kB — only pay for it once a signed message actually shows up. */
function getOpenPGP(): Promise<OpenPGP> {
    return openpgpPromise ??= import("openpgp");
}

/** messageId -> last known state. */
const cache = new Map<string, VerifyState>();
/** messageId -> in-flight check, so a re-render never starts a second verification. */
const inflight = new Map<string, Promise<VerifyState>>();

type Listener = (messageId: string, state: VerifyState) => void;
const listeners = new Set<Listener>();

export function subscribe(listener: Listener): () => void {
    listeners.add(listener);
    return () => void listeners.delete(listener);
}

function publish(messageId: string, state: VerifyState): VerifyState {
    cache.set(messageId, state);
    for (const l of listeners) {
        try {
            l(messageId, state);
        } catch {
            // A misbehaving badge must never break verification for other messages.
        }
    }
    return state;
}

export function getCached(messageId: string): VerifyState | undefined {
    return cache.get(messageId);
}

export function invalidate(messageId: string): void {
    cache.delete(messageId);
    inflight.delete(messageId);
}

export function clearCache(): void {
    cache.clear();
    inflight.clear();
}

/**
 * Returns the current state for a message, kicking off a check on first sight.
 * Safe to call from render: it is synchronous and idempotent.
 */
export interface VerifyRequest {
    messageId: string;
    content: string;
    /** Channel and author as rendered, plus the timestamp Discord recorded. */
    channelId: string;
    authorId: string;
    postedAt: number;
    hintUid?: string;
    /** How far the sender's clock may sit from Discord's, in seconds. */
    clockToleranceSec: number;
    /** Discord display name, kept alongside a pinned key so the entry stays readable. */
    username?: string;
    /** Pin the key of anyone whose first valid signature we see. */
    autoPin: boolean;
}

export function ensureVerified(req: VerifyRequest, opts: ResolverOptions): VerifyState {
    const { messageId, content, hintUid } = req;
    const cached = cache.get(messageId);
    if (cached) return cached;

    const decoded = decodeZeroWidthToSignature(content);
    if (!decoded.sigBuffer) {
        // The whole point of tracking signers: from someone who always signs, silence is the signal.
        const pinned = getTrustedSigner(req.authorId);
        return publish(messageId, pinned
            ? {
                status: VerifyStatus.MissingSignature,
                pinnedFingerprint: pinned.fingerprint,
                reason: `${pinned.username || "This account"} normally signs their messages.`
            }
            : { status: VerifyStatus.Unsigned });
    }

    if (!inflight.has(messageId)) {
        const task = runVerification(req, decoded.visibleText, decoded.sigBuffer, decoded.keyId, decoded.timestamp, opts)
            .catch<VerifyState>(e => ({ status: VerifyStatus.Error, reason: String(e?.message ?? e) }))
            .then(state => {
                inflight.delete(messageId);
                return publish(messageId, { keyId: decoded.keyId, ...state });
            });
        inflight.set(messageId, task);
    }

    return publish(messageId, { status: VerifyStatus.Pending, keyId: decoded.keyId, signedAt: decoded.timestamp });
}

async function runVerification(
    req: VerifyRequest,
    visibleText: string,
    sigBuffer: Uint8Array,
    keyId: string | undefined,
    timestamp: number | undefined,
    opts: ResolverOptions
): Promise<VerifyState> {
    const openpgp = await getOpenPGP();
    const { hintUid } = req;

    // What the sender actually signed. Without a timestamp the payload predates context binding
    // and only covers the bare text — it cannot be tied to this channel, author or moment.
    let signedText = visibleText;
    if (timestamp !== undefined) {
        const ctx: Partial<MessageContext> = {
            channelId: req.channelId,
            authorId: req.authorId,
            timestamp
        };
        if (!isUsableContext(ctx))
            return { status: VerifyStatus.Error, keyId, signedAt: timestamp, reason: "Message context is unreadable." };

        const drift = Math.abs(req.postedAt - timestamp);
        if (drift > req.clockToleranceSec) {
            return {
                status: VerifyStatus.Replayed,
                keyId,
                signedAt: timestamp,
                reason: `Signed ${formatDrift(drift)} before or after this message was posted.`
            };
        }

        signedText = canonicalSignedText(ctx, visibleText);
    }

    let signature: import("openpgp").Signature;
    try {
        signature = await openpgp.readSignature({ binarySignature: sigBuffer });
    } catch (e) {
        return { status: VerifyStatus.Error, reason: `Malformed signature packet: ${(e as Error).message}` };
    }

    // Prefer the key id the signature packet itself advertises over the payload header hint.
    const packetKeyId = signature.getSigningKeyIDs()[0]?.toHex().toUpperCase();
    const lookupId = packetKeyId ?? keyId;
    if (!lookupId)
        return { status: VerifyStatus.UnknownKey, reason: "Signature carries no key id." };

    const stored = await resolvePublicKey(lookupId, hintUid, opts);
    if (!stored)
        return { status: VerifyStatus.UnknownKey, keyId: lookupId };

    let publicKey: import("openpgp").PublicKey;
    try {
        publicKey = await openpgp.readKey({ armoredKey: stored.armored });
    } catch (e) {
        return { status: VerifyStatus.Error, keyId: lookupId, reason: `Unreadable public key: ${(e as Error).message}` };
    }

    const fingerprint = publicKey.getFingerprint().toUpperCase();
    const uid = stored.uid || (await safePrimaryUid(publicKey));

    try {
        const result = await openpgp.verify({
            message: await openpgp.createMessage({ text: signedText }),
            signature,
            verificationKeys: publicKey,
            expectSigned: true,
            // The signed data is the visible text exactly as gpg received it; no cleartext framing.
            format: "utf8"
        });
        // openpgp.js only surfaces a bad signature when this promise is awaited.
        await result.signatures[0].verified;
    } catch (e) {
        // A mismatch here cannot tell a rewritten text from a message lifted out of its channel:
        // both simply fail to reproduce the signed string. Say so rather than guess.
        return {
            status: VerifyStatus.Invalid,
            keyId: lookupId,
            fingerprint,
            uid,
            signedAt: timestamp,
            reason: timestamp === undefined
                ? (e as Error).message
                : "Text was edited, or the message was copied from another channel or author."
        };
    }

    // Pin on first sight, and refuse to let a second key quietly take over an enrolled account.
    const outcome = await recordVerified(
        req.authorId, req.username ?? "", fingerprint, lookupId, uid, req.autoPin
    );

    if (outcome === "mismatch") {
        return {
            status: VerifyStatus.KeyChanged,
            keyId: lookupId,
            fingerprint,
            uid,
            signedAt: timestamp,
            pinnedFingerprint: getTrustedSigner(req.authorId)?.fingerprint,
            reason: "This account has previously signed with a different key."
        };
    }

    return { status: VerifyStatus.Valid, keyId: lookupId, fingerprint, uid, signedAt: timestamp };
}

function formatDrift(seconds: number): string {
    if (seconds < 120) return `${Math.round(seconds)}s`;
    if (seconds < 7200) return `${Math.round(seconds / 60)}min`;
    return `${Math.round(seconds / 3600)}h`;
}

async function safePrimaryUid(key: import("openpgp").PublicKey): Promise<string> {
    try {
        return (await key.getPrimaryUser()).user.userID?.userID ?? key.getFingerprint().toUpperCase();
    } catch {
        return key.getFingerprint().toUpperCase();
    }
}

/** Parses an armored block pasted by the user, returning what we need to store it. */
export async function parseArmoredKey(armored: string): Promise<{ fingerprint: string; uid: string; }> {
    const openpgp = await getOpenPGP();
    const key = await openpgp.readKey({ armoredKey: armored.trim() });
    return { fingerprint: key.getFingerprint().toUpperCase(), uid: await safePrimaryUid(key) };
}
