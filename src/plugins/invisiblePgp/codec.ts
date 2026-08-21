/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Steganographic codec: arbitrary bytes <-> a run of invisible codepoints.
 *
 * Three alphabets are supported. Which one a message used is never declared anywhere — it is
 * recovered by decoding the run under every alphabet that could have produced it and keeping the
 * one that yields a well-formed frame. See `decodeMessage`.
 *
 *   base4   2 bits/codepoint  ZWSP, ZWNJ, ZWJ, WORD JOINER      (legacy, frame v1)
 *   base16  4 bits/codepoint  VS1-VS16    (U+FE00-U+FE0F)
 *   base256 8 bits/codepoint  VS1-VS256   (U+FE00-U+FE0F, U+E0100-U+E01EF)
 *
 * Density is not free. base16 halves the codepoint count against base4 and every symbol stays in
 * the BMP, so it is a win under any counting rule. base256 quarters the codepoint count, but 240
 * of its symbols are astral and cost two UTF-16 units each — whether that beats base16 depends on
 * how a given platform counts characters, which is a question for measurement, not for theory.
 * See SPEC.md; `tools/roundtrip-probe.mjs` produces the numbers.
 */

/** Frame version. v1 is base4 + the `ipgp1` canonical form; v2 is everything since. */
export const FRAME_V1 = 0x01;
export const FRAME_V2 = 0x02;

const FLAG_HAS_KEY_ID = 1 << 0;
/** Set when the signature covers the context binding rather than the bare text. */
const FLAG_HAS_CONTEXT = 1 << 1;
/** Every bit that means something. A frame setting any other bit is rejected — see parseFrame. */
const KNOWN_FLAGS = FLAG_HAS_KEY_ID | FLAG_HAS_CONTEXT;

const KEY_ID_LEN = 8;
const TIMESTAMP_LEN = 4;
const SIG_LEN_LEN = 2;

/**
 * Separates the payload from the user's text.
 *
 * A variation selector modifies the character it follows, and U+FE0F in particular is the emoji
 * presentation selector — appending one straight after a message could change how that message's
 * last character renders. U+034F COMBINING GRAPHEME JOINER is defined to have no visible effect
 * and belongs to no alphabet here, so it gives the first selector a harmless base character and
 * marks unambiguously where our run begins.
 */
export const ANCHOR = "͏";

export interface Alphabet {
    readonly name: "base4";
    readonly bitsPerSymbol: 2;
    /** Index in this array *is* the digit. Length is always 4. */
    readonly symbols: readonly string[];
}

/** ZWSP, ZWNJ, ZWJ, WORD JOINER. The only zero-width set that survives Discord. */
export const BASE4: Alphabet = {
    name: "base4",
    bitsPerSymbol: 2,
    symbols: ["\u200B", "\u200C", "\u200D", "\u2060"]
};

export const ALPHABETS = [BASE4] as const;

export type AlphabetName = Alphabet["name"];

export function alphabetByName(_name?: string): Alphabet {
    return BASE4;
}

/**
 * Per-alphabet symbol -> digit lookup.
 *
 * The alphabets are not disjoint: base16 is a strict subset of base256, since VS1-VS16 are the
 * first sixteen of the 256 variation selectors. So a run of characters cannot name its own
 * alphabet, and `decodeMessage` resolves it by trial instead.
 */
const DIGITS = new Map<Alphabet, ReadonlyMap<string, number>>(
    ALPHABETS.map(alphabet => [alphabet, new Map(alphabet.symbols.map((sym, digit) => [sym, digit]))])
);

/** Every character that could belong to some alphabet — used only to find the trailing run. */
const ANY_SYMBOL = new Set<string>(ALPHABETS.flatMap(a => [...a.symbols]));

/** Discord's hard limit for a plain (non-nitro) message, in UTF-16 units. */
export const DISCORD_MESSAGE_LIMIT = 2000;

export class PayloadTooLongError extends Error {
    constructor(public readonly overflow: number) {
        super(`Signed message exceeds Discord's ${DISCORD_MESSAGE_LIMIT} character limit by ${overflow} characters.`);
        this.name = "PayloadTooLongError";
    }
}

// ---------------------------------------------------------------------------------------------
// Bytes <-> symbols
// ---------------------------------------------------------------------------------------------

/** Encodes bytes as a run of invisible codepoints, most significant bits first. */
export function encodeBytes(bytes: Uint8Array, alphabet: Alphabet): string {
    const { bitsPerSymbol, symbols } = alphabet;
    const perByte = 8 / bitsPerSymbol;
    const mask = (1 << bitsPerSymbol) - 1;

    // Chunked join rather than repeated concatenation: meaningfully faster at payload sizes.
    const out = new Array<string>(bytes.length * perByte);
    let i = 0;
    for (const byte of bytes)
        for (let shift = 8 - bitsPerSymbol; shift >= 0; shift -= bitsPerSymbol)
            out[i++] = symbols[(byte >> shift) & mask];

    return out.join("");
}

/**
 * Inverse of {@link encodeBytes}.
 * @returns null when the run is not a whole number of bytes, or mixes alphabets.
 */
export function decodeBytes(run: string, alphabet: Alphabet): Uint8Array | null {
    const { bitsPerSymbol } = alphabet;
    const perByte = 8 / bitsPerSymbol;

    const table = DIGITS.get(alphabet)!;
    const digits: number[] = [];
    for (const ch of run) {
        const digit = table.get(ch);
        if (digit === undefined) return null;
        digits.push(digit);
    }

    if (digits.length === 0 || digits.length % perByte !== 0) return null;

    const bytes = new Uint8Array(digits.length / perByte);
    for (let b = 0; b < bytes.length; b++) {
        let value = 0;
        for (let d = 0; d < perByte; d++) value = (value << bitsPerSymbol) | digits[b * perByte + d];
        bytes[b] = value;
    }
    return bytes;
}

// ---------------------------------------------------------------------------------------------
// Frame
// ---------------------------------------------------------------------------------------------

export interface Frame {
    version: typeof FRAME_V1 | typeof FRAME_V2;
    sig: Uint8Array;
    /** 16 uppercase hex chars, when the sender included a key hint. */
    keyId?: string;
    /** Unix seconds; present exactly when the signature is context-bound. */
    timestamp?: number;
}

function hexToBytes(hex: string): Uint8Array {
    const out = new Uint8Array(hex.length >> 1);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
}

function bytesToHex(bytes: Uint8Array): string {
    let out = "";
    for (const b of bytes) out += b.toString(16).padStart(2, "0").toUpperCase();
    return out;
}

const KEY_ID_RE = /^[0-9a-fA-F]{16}$/;

/**
 * v1 reserved the 8 key-id bytes whether or not the flag was set. v2 omits them when the flag is
 * clear, which is why the header length depends on the version as well as on the flags.
 */
function headerLength(version: number, flags: number): number {
    const keyIdBytes = version === FRAME_V1 || (flags & FLAG_HAS_KEY_ID) ? KEY_ID_LEN : 0;
    const timestampBytes = flags & FLAG_HAS_CONTEXT ? TIMESTAMP_LEN : 0;
    return 2 + keyIdBytes + timestampBytes + SIG_LEN_LEN;
}

/** Wraps a raw detached signature in a v2 frame. */
export function buildFrame(sig: Uint8Array, keyId?: string, timestamp?: number): Uint8Array {
    if (sig.length === 0) throw new RangeError("Refusing to frame an empty signature");
    if (sig.length > 0xFFFF) throw new RangeError("Signature is too large to frame (>65535 bytes)");

    const hasKeyId = Boolean(keyId && KEY_ID_RE.test(keyId));
    const bound = Number.isInteger(timestamp) && (timestamp as number) > 0;
    if (bound && (timestamp as number) > 0xFFFFFFFF)
        throw new RangeError("Timestamp does not fit in 32 bits");

    const flags = (hasKeyId ? FLAG_HAS_KEY_ID : 0) | (bound ? FLAG_HAS_CONTEXT : 0);
    const headerLen = headerLength(FRAME_V2, flags);

    const frame = new Uint8Array(headerLen + sig.length);
    const view = new DataView(frame.buffer);
    frame[0] = FRAME_V2;
    frame[1] = flags;

    let o = 2;
    if (hasKeyId) {
        frame.set(hexToBytes(keyId as string), o);
        o += KEY_ID_LEN;
    }
    if (bound) {
        view.setUint32(o, timestamp as number);
        o += TIMESTAMP_LEN;
    }
    view.setUint16(o, sig.length);
    frame.set(sig, headerLen);

    return frame;
}

/** Inverse of {@link buildFrame}; also reads legacy v1 frames. Null for anything else. */
export function parseFrame(frame: Uint8Array): Frame | null {
    if (frame.length < 2) return null;

    const version = frame[0];
    if (version !== FRAME_V1 && version !== FRAME_V2) return null;

    const flags = frame[1];
    // Unused bits are rejected rather than ignored, so that each frame has exactly one byte
    // representation. Otherwise two different payloads could parse to the same signature, and a
    // relay could reword a frame without changing what it decodes to.
    if (flags & ~KNOWN_FLAGS) return null;

    const headerLen = headerLength(version, flags);
    if (frame.length < headerLen) return null;

    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);

    let o = 2;
    let keyId: string | undefined;
    if (version === FRAME_V1 || flags & FLAG_HAS_KEY_ID) {
        if (flags & FLAG_HAS_KEY_ID) keyId = bytesToHex(frame.subarray(o, o + KEY_ID_LEN));
        o += KEY_ID_LEN;
    }

    let timestamp: number | undefined;
    if (flags & FLAG_HAS_CONTEXT) {
        timestamp = view.getUint32(o);
        o += TIMESTAMP_LEN;
    }

    const sigLen = view.getUint16(o);
    o += SIG_LEN_LEN;

    // Rejecting a length that does not account for every remaining byte is what stops a run padded
    // with stray invisible characters from being read as a shorter, valid signature.
    if (sigLen === 0 || o + sigLen !== frame.length) return null;

    return { version: version as Frame["version"], sig: frame.slice(o), keyId, timestamp };
}

// ---------------------------------------------------------------------------------------------
// Message <-> payload
// ---------------------------------------------------------------------------------------------

export interface DecodedMessage {
    /** The message with the payload run removed. Identical to the input when there is no payload. */
    visibleText: string;
    /** Parsed frame, or null when the message carries no well-formed payload. */
    frame: Frame | null;
    /** Which alphabet the payload used. */
    alphabet?: Alphabet;
}

/**
 * Finds the trailing run of payload characters.
 *
 * Deliberately *not* a global strip. U+FE0F is the emoji presentation selector, so removing every
 * alphabet character wherever it appears would quietly rewrite any emoji the user actually typed
 * (`❤️` is U+2764 U+FE0F). Only a contiguous run at the very end can be ours, because that is the
 * only place we ever write one.
 */
function findTrailingRun(text: string): { visibleText: string; run: string; } {
    const chars = [...text];
    let start = chars.length;
    while (start > 0 && ANY_SYMBOL.has(chars[start - 1])) start--;

    // Consume the anchor too, so it never leaks into the visible text.
    let visibleEnd = start;
    if (visibleEnd > 0 && chars[visibleEnd - 1] === ANCHOR) visibleEnd--;

    return { visibleText: chars.slice(0, visibleEnd).join(""), run: chars.slice(start).join("") };
}

/** True if the text ends in a run that parses as one of our frames. */
export function hasPayload(text: string): boolean {
    return decodeMessage(text).frame !== null;
}

/**
 * Splits a message into its visible text and the signature hidden at the end of it.
 *
 * When there is no valid payload, `visibleText` is the input untouched — a message is never
 * altered on the strength of a guess.
 */
export function decodeMessage(text: string): DecodedMessage {
    const unsigned: DecodedMessage = { visibleText: text, frame: null };

    const { visibleText, run } = findTrailingRun(text);
    if (run.length === 0) return unsigned;

    // Try every alphabet. A run only decodes to a valid frame under the alphabet that wrote it:
    // any other reading has to land on a known version byte *and* a length field that accounts for
    // exactly the remaining bytes, which is not something a misreading does by accident.
    const candidates: DecodedMessage[] = [];
    for (const alphabet of ALPHABETS) {
        const bytes = decodeBytes(run, alphabet);
        if (!bytes) continue;

        const frame = parseFrame(bytes);
        if (!frame) continue;

        // A v1 frame is base4 by definition; anything else is a forgery or a bug, not a v1 message.
        if (frame.version === FRAME_V1 && alphabet !== BASE4) continue;

        candidates.push({ visibleText, frame, alphabet });
    }

    // Two readings of the same run is not a verdict we can defend, so it is not one we return.
    if (candidates.length !== 1) return unsigned;

    return candidates[0];
}

/** Builds the invisible run to append to a message. */
export function encodePayload(
    sig: Uint8Array,
    alphabetOrKeyId?: Alphabet | string,
    keyIdOrTs?: string | number,
    timestamp?: number
): string {
    let alphabet: Alphabet = BASE4;
    let keyId: string | undefined;
    let ts: number | undefined;

    if (typeof alphabetOrKeyId === "object" && alphabetOrKeyId !== null && "symbols" in alphabetOrKeyId) {
        alphabet = alphabetOrKeyId;
        keyId = typeof keyIdOrTs === "string" ? keyIdOrTs : undefined;
        ts = timestamp;
    } else {
        keyId = typeof alphabetOrKeyId === "string" ? alphabetOrKeyId : undefined;
        ts = typeof keyIdOrTs === "number" ? keyIdOrTs : undefined;
    }

    return ANCHOR + encodeBytes(buildFrame(sig, keyId, ts), alphabet);
}

/**
 * Appends a payload to a message, guarding the platform's length limit.
 *
 * Suffixed rather than prefixed: trailing invisible characters survive Discord's whitespace
 * trimming, leading ones do not.
 *
 * @throws {PayloadTooLongError} when the result would be rejected.
 */
export function attachPayload(visibleText: string, payload: string, limit = DISCORD_MESSAGE_LIMIT): string {
    // .length is UTF-16 units, which is what the platforms in question actually count.
    const total = visibleText.length + payload.length;
    if (total > limit) throw new PayloadTooLongError(total - limit);
    return visibleText + payload;
}
