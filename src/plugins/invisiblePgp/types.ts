/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/** Error codes surfaced by the native gpg bridge. */
export const enum GpgErrorCode {
    /** The gpg binary could not be spawned at all. */
    NoGpg = "NO_GPG",
    /** --local-user did not match any secret key. */
    KeyNotFound = "KEY_NOT_FOUND",
    /** Smartcard/YubiKey was not present or got unplugged mid-operation. */
    CardRemoved = "CARD_REMOVED",
    /** Wrong PIN, or the card is blocked. */
    BadPin = "BAD_PIN",
    /** The user never touched the key (or never entered the PIN) in time. */
    TouchTimeout = "TOUCH_TIMEOUT",
    Unknown = "UNKNOWN"
}

export interface GpgKeyInfo {
    /** Full uppercase fingerprint. */
    fingerprint: string;
    /** Last 16 hex chars of the fingerprint. */
    keyId: string;
    /** Primary user id, e.g. "Alice <alice@example.com>". */
    uid: string;
    /** e.g. "ed25519", "rsa4096". */
    algo: string;
    /** True when the secret key material lives on a smartcard (YubiKey). */
    onCard: boolean;
}

export type NativeSignResult =
    | { ok: true; sig: number[]; }
    | { ok: false; code: GpgErrorCode; error: string; };

/** Lifecycle of an inbound message's signature check. */
export const enum VerifyStatus {
    /** No zero-width payload found on the message. */
    Unsigned = "UNSIGNED",
    /** Verification is in flight. */
    Pending = "PENDING",
    Valid = "VALID",
    /** Payload present but the signature does not match the visible text. */
    Invalid = "INVALID",
    /** Payload present, but no public key could be resolved for it. */
    UnknownKey = "UNKNOWN_KEY",
    /** Signature is cryptographically valid, but was made for another channel, author or moment. */
    Replayed = "REPLAYED",
    /** No signature at all, from someone who is expected to sign. */
    MissingSignature = "MISSING_SIGNATURE",
    /** Valid signature, but from a different key than the one pinned for this account. */
    KeyChanged = "KEY_CHANGED",
    /** Malformed payload, network failure, openpgp.js blew up, ... */
    Error = "ERROR"
}

export interface VerifyState {
    status: VerifyStatus;
    /** Short key id carried in the payload header, when present. */
    keyId?: string;
    /** Full fingerprint of the key that made the signature (once resolved). */
    fingerprint?: string;
    /** Primary uid of the signing key. */
    uid?: string;
    /** Human readable detail, shown in the badge tooltip on failure. */
    reason?: string;
    /** When the sender claims to have signed, as unix seconds. */
    signedAt?: number;
    /** Fingerprint previously pinned for this account, when it differs from the one used. */
    pinnedFingerprint?: string;
}

export interface StoredKey {
    /** ASCII-armored public key block. */
    armored: string;
    uid: string;
    /**
     * Full uppercase fingerprint. A key fetched from the network starts out with only the 16-hex
     * key id here (that is all the lookup knew); `refineStoredKey` replaces it with the real
     * fingerprint the first time openpgp.js parses the key. `provisionalFingerprint` says which.
     */
    fingerprint: string;
    /** True while `fingerprint` is still just the 16-hex key id and must not be shown as one. */
    provisionalFingerprint?: boolean;
    /** Epoch millis of the last successful fetch/import. */
    fetchedAt: number;
    /** True when the user pasted it in by hand — never expires, never refetched. */
    manual: boolean;
}
