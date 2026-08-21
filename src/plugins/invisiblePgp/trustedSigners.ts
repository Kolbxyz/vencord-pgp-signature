/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import * as DataStore from "@api/DataStore";

/**
 * Who is expected to sign.
 *
 * A signature is a positive proof: it says what someone did write, never what they did not. So an
 * unsigned message is normally meaningless — until you know that this particular person always
 * signs. This module keeps that expectation, which is what turns a missing signature into a visible
 * anomaly rather than silence.
 *
 * Enrolment is trust-on-first-use: the first valid signature seen from someone pins their key. Any
 * later message signed by a *different* key is flagged instead of silently accepted, so an attacker
 * cannot enrol their own key over an existing one.
 */

const STORE_KEY = "InvisiblePGP_trustedSigners";

export interface TrustedSigner {
    /** Full fingerprint of the key pinned for this account. */
    fingerprint: string;
    keyId: string;
    /** OpenPGP uid at pinning time, for display. */
    uid: string;
    /** Discord username at pinning time, so the entry stays readable after a rename. */
    username: string;
    addedAt: number;
    lastSeenAt: number;
    /** "manual" entries are never overwritten by trust-on-first-use. */
    source: "manual" | "detected";
}

/** discordUserId -> pinned signer. Mirrored in memory so the badge can read it during render. */
let signers: Record<string, TrustedSigner> = {};
let loaded = false;

export async function loadTrustedSigners(): Promise<void> {
    if (loaded) return;
    signers = (await DataStore.get<Record<string, TrustedSigner>>(STORE_KEY)) ?? {};
    loaded = true;
}

export function getTrustedSigners(): Record<string, TrustedSigner> {
    return signers;
}

/** Synchronous by design: called from the render path, where an await would flash the wrong badge. */
export function getTrustedSigner(userId: string): TrustedSigner | undefined {
    return signers[userId];
}

export function isTracked(userId: string): boolean {
    return Boolean(signers[userId]);
}

async function persist(): Promise<void> {
    await DataStore.set(STORE_KEY, signers);
}

export async function pinSigner(userId: string, signer: TrustedSigner): Promise<void> {
    await loadTrustedSigners();
    signers[userId] = signer;
    await persist();
}

export async function unpinSigner(userId: string): Promise<void> {
    await loadTrustedSigners();
    delete signers[userId];
    await persist();
}

/**
 * Records a verified signature.
 * @returns "pinned" on first sight, "refreshed" for the same key again, "mismatch" when the account
 *          signed with a key other than the pinned one — which the caller must surface, not ignore.
 */
export async function recordVerified(
    userId: string,
    username: string,
    fingerprint: string,
    keyId: string,
    uid: string,
    autoPin: boolean
): Promise<"pinned" | "refreshed" | "mismatch" | "ignored"> {
    await loadTrustedSigners();
    const known = signers[userId];

    if (!known) {
        if (!autoPin) return "ignored";
        signers[userId] = {
            fingerprint, keyId, uid, username,
            addedAt: Date.now(), lastSeenAt: Date.now(),
            source: "detected"
        };
        await persist();
        return "pinned";
    }

    if (known.fingerprint !== fingerprint) return "mismatch";

    known.lastSeenAt = Date.now();
    known.username = username;
    await persist();
    return "refreshed";
}
