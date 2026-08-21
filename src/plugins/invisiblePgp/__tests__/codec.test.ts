/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { describe, expect, it } from "vitest";

import {
    ALPHABETS, Alphabet, alphabetByName, ANCHOR, attachPayload, BASE4,
    buildFrame, decodeBytes, decodeMessage, DISCORD_MESSAGE_LIMIT, encodeBytes, encodePayload,
    FRAME_V1, FRAME_V2, hasPayload, parseFrame, PayloadTooLongError
} from "../codec";

/** A stand-in for a real gpg Ed25519 detached signature: 119 bytes, no structure needed. */
const SIG = new Uint8Array(119).map((_, i) => (i * 7 + 13) & 0xFF);
const KEY_ID = "A1B2C3D4E5F60718";
const TS = 1787314443;

describe("alphabets", () => {
    it.each(ALPHABETS)("$name has exactly 2**bits symbols, all single codepoints", alphabet => {
        expect(alphabet.symbols).toHaveLength(2 ** alphabet.bitsPerSymbol);
        for (const symbol of alphabet.symbols) expect([...symbol]).toHaveLength(1);
    });

    it("never uses the anchor as a symbol", () => {
        for (const alphabet of ALPHABETS) expect(alphabet.symbols).not.toContain(ANCHOR);
    });

    it("resolves by name", () => {
        expect(alphabetByName("base4")).toBe(BASE4);
    });
});

describe.each(ALPHABETS)("byte codec — $name", (alphabet: Alphabet) => {
    it("round-trips every possible byte value", () => {
        const all = new Uint8Array(256).map((_, i) => i);
        expect(decodeBytes(encodeBytes(all, alphabet), alphabet)).toEqual(all);
    });

    it("produces exactly 8 / bitsPerSymbol codepoints per byte", () => {
        const encoded = encodeBytes(new Uint8Array(10), alphabet);
        expect([...encoded]).toHaveLength(10 * (8 / alphabet.bitsPerSymbol));
    });

    it("rejects a run that is not a whole number of bytes", () => {
        const partial = [...encodeBytes(SIG, alphabet)].slice(0, -1).join("");
        expect(decodeBytes(partial, alphabet)).toBeNull();
    });

    it("rejects an invalid character not in alphabet", () => {
        expect(decodeBytes(encodeBytes(SIG, alphabet) + "A", alphabet)).toBeNull();
    });

    it("rejects an empty run", () => {
        expect(decodeBytes("", alphabet)).toBeNull();
    });
});

describe("frame", () => {
    it("round-trips a signature with a key id and a timestamp", () => {
        const frame = parseFrame(buildFrame(SIG, KEY_ID, TS))!;
        expect(frame.version).toBe(FRAME_V2);
        expect(frame.sig).toEqual(SIG);
        expect(frame.keyId).toBe(KEY_ID);
        expect(frame.timestamp).toBe(TS);
    });

    it("omits both optional fields when they are not supplied", () => {
        const frame = parseFrame(buildFrame(SIG))!;
        expect(frame.keyId).toBeUndefined();
        expect(frame.timestamp).toBeUndefined();
        // v1 always reserved the 8 key-id bytes; v2 spends them only when there is a key id.
        expect(buildFrame(SIG).length).toBe(buildFrame(SIG, KEY_ID).length - 8);
    });

    it("uppercases the key id regardless of how it was given", () => {
        expect(parseFrame(buildFrame(SIG, KEY_ID.toLowerCase()))!.keyId).toBe(KEY_ID);
    });

    it("ignores a malformed key id rather than framing garbage", () => {
        expect(parseFrame(buildFrame(SIG, "not-hex"))!.keyId).toBeUndefined();
    });

    it("carries a timestamp at the top of the 32-bit range", () => {
        expect(parseFrame(buildFrame(SIG, undefined, 0xFFFFFFFF))!.timestamp).toBe(0xFFFFFFFF);
    });

    it("refuses to build a frame it could not honestly describe", () => {
        expect(() => buildFrame(new Uint8Array(0))).toThrow(RangeError);
        expect(() => buildFrame(new Uint8Array(0x10000))).toThrow(RangeError);
        expect(() => buildFrame(SIG, undefined, 0x1_0000_0000)).toThrow(RangeError);
    });

    it("rejects an unknown version byte", () => {
        const frame = buildFrame(SIG, KEY_ID, TS);
        frame[0] = 0x03;
        expect(parseFrame(frame)).toBeNull();
    });

    it("rejects a truncated frame", () => {
        const frame = buildFrame(SIG, KEY_ID, TS);
        for (const cut of [1, 5, 12, frame.length - 1])
            expect(parseFrame(frame.slice(0, cut))).toBeNull();
    });

    it("rejects trailing bytes that the declared length does not account for", () => {
        const frame = buildFrame(SIG, KEY_ID, TS);
        const padded = new Uint8Array(frame.length + 3);
        padded.set(frame);
        expect(parseFrame(padded)).toBeNull();
    });

    it("still reads a legacy v1 frame", () => {
        // v1 layout: magic | flags | keyId(8, always present) | [ts(4)] | sigLen(2) | sig
        const sig = new Uint8Array([1, 2, 3, 4]);
        const frame = new Uint8Array(16 + sig.length);
        frame[0] = FRAME_V1;
        frame[1] = 0b11;
        frame.set([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11], 2);
        new DataView(frame.buffer).setUint32(10, TS);
        new DataView(frame.buffer).setUint16(14, sig.length);
        frame.set(sig, 16);

        const parsed = parseFrame(frame)!;
        expect(parsed.version).toBe(FRAME_V1);
        expect(parsed.keyId).toBe("AABBCCDDEEFF0011");
        expect(parsed.timestamp).toBe(TS);
        expect(parsed.sig).toEqual(sig);
    });
});

describe.each(ALPHABETS)("message round trip — $name", (alphabet: Alphabet) => {
    const attach = (text: string) => text + encodePayload(SIG, alphabet, KEY_ID, TS);

    it("recovers the text and the signature unchanged", () => {
        const text = "Hello, this message is signed. Emoji: 🔐🗝️";
        const decoded = decodeMessage(attach(text));
        expect(decoded.visibleText).toBe(text);
        expect(decoded.frame!.sig).toEqual(SIG);
        expect(decoded.frame!.keyId).toBe(KEY_ID);
        expect(decoded.frame!.timestamp).toBe(TS);
        expect(decoded.alphabet).toBe(alphabet);
    });

    it("identifies the alphabet from the characters alone", () => {
        expect(decodeMessage(attach("x")).alphabet!.name).toBe(alphabet.name);
    });

    it("survives an empty visible message", () => {
        expect(decodeMessage(attach("")).visibleText).toBe("");
    });

    it("reports a payload via hasPayload", () => {
        expect(hasPayload(attach("hi"))).toBe(true);
    });

    it("refuses a truncated payload instead of decoding a shorter signature", () => {
        const message = attach("hello");
        const chars = [...message];
        expect(decodeMessage(chars.slice(0, chars.length - 10).join("")).frame).toBeNull();
    });

    it("refuses a payload padded with extra symbols", () => {
        expect(decodeMessage(attach("hello") + alphabet.symbols[0]).frame).toBeNull();
    });
});

describe("decoding is conservative", () => {
    it("leaves an unsigned message byte-for-byte untouched", () => {
        for (const text of ["just a normal message", "", "   ", "no payload here 🔐"]) {
            const decoded = decodeMessage(text);
            expect(decoded.frame).toBeNull();
            expect(decoded.visibleText).toBe(text);
        }
    });

    it("does not strip the variation selector out of a real emoji", () => {
        // ❤️ is U+2764 U+FE0F — U+FE0F is also a base16/base256 symbol. A global strip would eat it.
        const text = "I ❤️ you 👍🏽";
        expect(decodeMessage(text).visibleText).toBe(text);
        expect(hasPayload(text)).toBe(false);
    });

    it("keeps an emoji intact when the message really is signed", () => {
        const text = "ends in an emoji ❤️";
        const decoded = decodeMessage(text + encodePayload(SIG, BASE4, KEY_ID, TS));
        expect(decoded.visibleText).toBe(text);
        expect(decoded.frame!.sig).toEqual(SIG);
    });

    it("ignores stray invisible characters scattered through the text", () => {
        const text = `a${BASE4.symbols[0]}b${BASE4.symbols[1]}c`;
        expect(decodeMessage(text).frame).toBeNull();
        expect(decodeMessage(text).visibleText).toBe(text);
    });

    it("reads a legacy base4 message that has no anchor", () => {
        expect(decodeMessage("legacy" + encodeBytes(buildFrame(SIG, KEY_ID, TS), BASE4)).frame!.sig)
            .toEqual(SIG);
    });
});

describe("attachPayload", () => {
    it("appends rather than prepends, so trimming cannot eat the payload", () => {
        expect(attachPayload("hi", "PAYLOAD")).toBe("hiPAYLOAD");
    });

    it("throws with the exact overflow once past the limit", () => {
        const text = "x".repeat(DISCORD_MESSAGE_LIMIT - 5);
        expect(() => attachPayload(text, "y".repeat(12))).toThrow(PayloadTooLongError);
        try {
            attachPayload(text, "y".repeat(12));
        } catch (e) {
            expect((e as PayloadTooLongError).overflow).toBe(7);
        }
    });

    it("accepts a message that lands exactly on the limit", () => {
        expect(attachPayload("x".repeat(1990), "y".repeat(10))).toHaveLength(DISCORD_MESSAGE_LIMIT);
    });
});
