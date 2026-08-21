/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Base-4 steganographic codec.
 *
 * Every byte of the payload becomes exactly four zero-width codepoints (2 bits each, MSB first),
 * which is the densest encoding that still only uses codepoints Discord reliably round-trips.
 * A detached Ed25519 signature is ~100 bytes, so a signed message carries ~450 invisible chars.
 */

/** ZWSP, ZWNJ, ZWJ, WORD JOINER — index in this array *is* the base-4 digit. */
const ALPHABET = ["​", "‌", "‍", "⁠"] as const;

const DIGIT_OF = new Map<string, number>(ALPHABET.map((c, i) => [c, i]));

/** Frame version. Bumped if the header layout ever changes. */
const MAGIC = 0x01;

const FLAG_HAS_KEY_ID = 1 << 0;
/** Set when the signature covers the context binding, not the bare text. */
const FLAG_HAS_CONTEXT = 1 << 1;

/** magic(1) + flags(1) + keyId(8) [+ timestamp(4)] + sigLen(2) */
const BASE_HEADER_LEN = 12;
const TIMESTAMP_LEN = 4;
const KEY_ID_OFFSET = 2;
const KEY_ID_LEN = 8;
const TIMESTAMP_OFFSET = 10;

/** Discord's hard limit for a plain (non-nitro) message. */
export const DISCORD_MESSAGE_LIMIT = 2000;

export class PayloadTooLongError extends Error {
    constructor(public readonly overflow: number) {
        super(`Signed message exceeds Discord's ${DISCORD_MESSAGE_LIMIT} character limit by ${overflow} characters.`);
        this.name = "PayloadTooLongError";
    }
}

export interface DecodedPayload {
    /** The message with every zero-width codepoint of our alphabet stripped out. */
    visibleText: string;
    /** Raw detached signature, or null when there is no (valid) payload. */
    sigBuffer: Uint8Array | null;
    /** 16 hex chars, when the sender included a key hint. */
    keyId?: string;
    /** Unix seconds the sender signed at, when the payload is context-bound. */
    timestamp?: number;
}

/** True if the text contains at least one codepoint from our alphabet. */
export function hasZeroWidthPayload(text: string): boolean {
    for (const ch of text) if (DIGIT_OF.has(ch)) return true;
    return false;
}

/** Strips our alphabet out of a string without attempting to decode it. */
export function stripZeroWidth(text: string): string {
    let out = "";
    for (const ch of text) if (!DIGIT_OF.has(ch)) out += ch;
    return out;
}

function hexToBytes(hex: string): Uint8Array {
    const out = new Uint8Array(hex.length >> 1);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
}

function bytesToHex(bytes: Uint8Array): string {
    let out = "";
    for (const b of bytes) out += b.toString(16).padStart(2, "0").toUpperCase();
    return out;
}

/**
 * Wraps a raw detached signature in our header.
 * @param keyId 16 hex chars (last 8 bytes of the fingerprint).
 * @param timestamp unix seconds; present exactly when the signature is context-bound.
 */
export function buildFrame(sigBuffer: Uint8Array, keyId?: string, timestamp?: number): Uint8Array {
    if (sigBuffer.length > 0xffff)
        throw new RangeError("Signature is too large to frame (>65535 bytes)");

    const bound = Number.isInteger(timestamp) && (timestamp as number) > 0;
    const headerLen = BASE_HEADER_LEN + (bound ? TIMESTAMP_LEN : 0);

    const frame = new Uint8Array(headerLen + sigBuffer.length);
    frame[0] = MAGIC;

    if (keyId && /^[0-9a-fA-F]{16}$/.test(keyId)) {
        frame[1] |= FLAG_HAS_KEY_ID;
        frame.set(hexToBytes(keyId), KEY_ID_OFFSET);
    }

    let o = TIMESTAMP_OFFSET;
    if (bound) {
        frame[1] |= FLAG_HAS_CONTEXT;
        new DataView(frame.buffer).setUint32(TIMESTAMP_OFFSET, timestamp as number);
        o += TIMESTAMP_LEN;
    }

    frame[o] = (sigBuffer.length >> 8) & 0xff;
    frame[o + 1] = sigBuffer.length & 0xff;
    frame.set(sigBuffer, headerLen);

    return frame;
}

/** Inverse of {@link buildFrame}. Returns null for anything that isn't one of our frames. */
export function parseFrame(frame: Uint8Array): { sig: Uint8Array; keyId?: string; timestamp?: number; } | null {
    if (frame.length < BASE_HEADER_LEN || frame[0] !== MAGIC) return null;

    const bound = Boolean(frame[1] & FLAG_HAS_CONTEXT);
    const headerLen = BASE_HEADER_LEN + (bound ? TIMESTAMP_LEN : 0);
    if (frame.length < headerLen) return null;

    const lenOffset = bound ? TIMESTAMP_OFFSET + TIMESTAMP_LEN : TIMESTAMP_OFFSET;
    const sigLen = (frame[lenOffset] << 8) | frame[lenOffset + 1];
    // Reject truncated payloads and payloads padded with foreign zero-width chars.
    if (headerLen + sigLen !== frame.length || sigLen === 0) return null;

    const keyId = (frame[1] & FLAG_HAS_KEY_ID)
        ? bytesToHex(frame.subarray(KEY_ID_OFFSET, KEY_ID_OFFSET + KEY_ID_LEN))
        : undefined;

    const timestamp = bound
        ? new DataView(frame.buffer, frame.byteOffset).getUint32(TIMESTAMP_OFFSET)
        : undefined;

    return { sig: frame.slice(headerLen), keyId, timestamp };
}

/** Encodes arbitrary bytes as zero-width codepoints. */
export function encodeBytesToZeroWidth(bytes: Uint8Array): string {
    // Chunked join is meaningfully faster than repeated string concat for ~500 char payloads.
    const out = new Array<string>(bytes.length * 4);
    let i = 0;
    for (const byte of bytes) {
        out[i++] = ALPHABET[(byte >> 6) & 0b11];
        out[i++] = ALPHABET[(byte >> 4) & 0b11];
        out[i++] = ALPHABET[(byte >> 2) & 0b11];
        out[i++] = ALPHABET[byte & 0b11];
    }
    return out.join("");
}

/**
 * Encodes a detached signature into an invisible string, header included.
 * Pass `keyId` (16 hex chars) so the receiver can resolve the public key without guessing.
 */
export function encodeSignatureToZeroWidth(sigBuffer: Uint8Array, keyId?: string, timestamp?: number): string {
    return encodeBytesToZeroWidth(buildFrame(sigBuffer, keyId, timestamp));
}

/**
 * Splits a message into its visible text and the detached signature hidden inside it.
 * `sigBuffer` is null when there is no payload, or when the payload is not a well-formed frame.
 */
export function decodeZeroWidthToSignature(rawText: string): DecodedPayload {
    const visible: string[] = [];
    const digits: number[] = [];

    for (const ch of rawText) {
        const digit = DIGIT_OF.get(ch);
        if (digit === undefined) visible.push(ch);
        else digits.push(digit);
    }

    const visibleText = visible.join("");
    if (digits.length === 0 || digits.length % 4 !== 0)
        return { visibleText, sigBuffer: null };

    const frame = new Uint8Array(digits.length / 4);
    for (let i = 0; i < frame.length; i++) {
        const o = i * 4;
        frame[i] = (digits[o] << 6) | (digits[o + 1] << 4) | (digits[o + 2] << 2) | digits[o + 3];
    }

    const parsed = parseFrame(frame);
    if (!parsed) return { visibleText, sigBuffer: null };

    return { visibleText, sigBuffer: parsed.sig, keyId: parsed.keyId, timestamp: parsed.timestamp };
}

/**
 * Appends an encoded payload to a message, guarding Discord's length limit.
 * @throws {PayloadTooLongError} when the result would be rejected by Discord.
 */
export function attachPayload(visibleText: string, payload: string): string {
    const total = visibleText.length + payload.length;
    if (total > DISCORD_MESSAGE_LIMIT)
        throw new PayloadTooLongError(total - DISCORD_MESSAGE_LIMIT);

    // Suffixed: trailing zero-width chars survive Discord's whitespace trimming, leading ones don't.
    return visibleText + payload;
}
