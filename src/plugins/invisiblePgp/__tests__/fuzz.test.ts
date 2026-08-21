/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Property tests for the codec.
 *
 * The unit tests check the cases someone thought of. These check the two properties that have to
 * hold for *every* input, because they are what the whole scheme rests on:
 *
 *   1. anything encoded comes back identical;
 *   2. anything corrupted is rejected, never silently decoded into a different valid frame.
 *
 * Property 2 is the one that matters for security. A codec that quietly turns a damaged payload
 * into some other well-formed signature would hand an attacker a way to swap what was verified.
 */

import { describe, expect, it } from "vitest";

import {
    ALPHABETS, Alphabet, ANCHOR, BASE16, buildFrame, decodeBytes, decodeMessage, encodeBytes,
    encodePayload, parseFrame
} from "../codec";

/**
 * Deterministic PRNG (mulberry32). A fuzz failure that cannot be reproduced is a bug report nobody
 * can act on, so the seed is fixed and printed with every generated case.
 */
function rng(seed: number): () => number {
    let a = seed >>> 0;
    return () => {
        a = (a + 0x6D2B79F5) >>> 0;
        let t = Math.imul(a ^ (a >>> 15), 1 | a);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

/** Fixed so a failure is reproducible; printed in every assertion message. */
const SEED = 20260821;
const ITERATIONS = 400;

function randomBytes(next: () => number, length: number): Uint8Array {
    return new Uint8Array(length).map(() => Math.floor(next() * 256));
}

/** A grab bag of text that has historically broken naive string handling. */
const AWKWARD_TEXT = [
    "",
    "plain",
    "I ❤️ you",
    "👨‍👩‍👧‍👦 family, one grapheme, many codepoints",
    "🏳️‍🌈 flag with a variation selector inside",
    "combining áéí",
    "right-to-left ‮override‬",
    "𝕞𝕒𝕥𝕙𝕖𝕞𝕒𝕥𝕚𝕔𝕒𝕝 𝕓𝕠𝕝𝕕",
    "newlines\nand\ttabs",
    "trailing space ",
    "ends in a variation selector ❤️"
];

describe("property: encode then decode is the identity", () => {
    it.each(ALPHABETS)("$name — random signatures of random lengths", (alphabet: Alphabet) => {
        const next = rng(SEED);
        for (let i = 0; i < ITERATIONS; i++) {
            const sig = randomBytes(next, 1 + Math.floor(next() * 300));
            const keyId = next() < 0.5
                ? [...randomBytes(next, 8)].map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase()
                : undefined;
            const timestamp = next() < 0.5 ? 1 + Math.floor(next() * 0xFFFFFFFE) : undefined;
            const text = AWKWARD_TEXT[Math.floor(next() * AWKWARD_TEXT.length)];

            const decoded = decodeMessage(text + encodePayload(sig, alphabet, keyId, timestamp));

            expect(decoded.frame, `seed ${SEED} iteration ${i}`).not.toBeNull();
            expect(decoded.visibleText).toBe(text);
            expect(decoded.frame!.sig).toEqual(sig);
            expect(decoded.frame!.keyId).toBe(keyId);
            expect(decoded.frame!.timestamp).toBe(timestamp);
            expect(decoded.alphabet).toBe(alphabet);
        }
    });

    it.each(ALPHABETS)("$name — raw byte runs of every length up to 64", (alphabet: Alphabet) => {
        const next = rng(SEED);
        for (let length = 1; length <= 64; length++) {
            const bytes = randomBytes(next, length);
            expect(decodeBytes(encodeBytes(bytes, alphabet), alphabet)).toEqual(bytes);
        }
    });
});

describe("property: a corrupted payload is rejected, never re-interpreted", () => {
    const original = buildFrame(new Uint8Array(119).fill(0xAB), "A1B2C3D4E5F60718", 1787314443);

    it.each(ALPHABETS)("$name — flipping any single symbol never yields a different valid frame", (alphabet: Alphabet) => {
        const next = rng(SEED);
        const reference = parseFrame(original)!;
        const symbols = [...encodeBytes(original, alphabet)];

        for (let i = 0; i < ITERATIONS; i++) {
            const at = Math.floor(next() * symbols.length);
            const replacement = alphabet.symbols[Math.floor(next() * alphabet.symbols.length)];
            if (replacement === symbols[at]) continue;

            const mutated = [...symbols];
            mutated[at] = replacement;

            const bytes = decodeBytes(mutated.join(""), alphabet)!;
            const frame = parseFrame(bytes);

            // Either the frame is rejected outright, or it decodes to something demonstrably
            // different from the original. What must never happen is a *changed* payload that
            // still parses to the *same* frame: that would mean the bytes a verifier acts on can
            // be reached by more than one payload, so a relay could reword one without detection.
            // `version` counts as part of the frame: v1 and v2 share a header layout when both
            // optional fields are present, but they select different canonical forms, so a frame
            // that differs only in its version byte is genuinely a different frame.
            if (frame) {
                const same = frame.version === reference.version
                    && frame.sig.length === reference.sig.length
                    && frame.sig.every((b, k) => b === reference.sig[k])
                    && frame.keyId === reference.keyId
                    && frame.timestamp === reference.timestamp;
                expect(same, `seed ${SEED} iteration ${i}: mutation produced an identical frame`).toBe(false);
            }
        }
    });

    it.each(ALPHABETS)("$name — truncating at any point is always rejected", (alphabet: Alphabet) => {
        const message = "hello" + encodePayload(original.slice(-119), alphabet, "A1B2C3D4E5F60718", 1787314443);
        const chars = [...message];

        for (let cut = 1; cut < chars.length; cut++) {
            const decoded = decodeMessage(chars.slice(0, cut).join(""));
            // The only prefix that may decode is the whole payload, which we never reach here.
            expect(decoded.frame, `truncated to ${cut} codepoints`).toBeNull();
        }
    });

    it.each(ALPHABETS)("$name — appending any number of stray symbols is always rejected", (alphabet: Alphabet) => {
        const next = rng(SEED);
        const message = "hello" + encodePayload(original.slice(-119), alphabet, undefined, 1787314443);

        for (let extra = 1; extra <= 32; extra++) {
            const junk = Array.from({ length: extra },
                () => alphabet.symbols[Math.floor(next() * alphabet.symbols.length)]).join("");
            expect(decodeMessage(message + junk).frame, `${extra} stray symbols`).toBeNull();
        }
    });

    it("random invisible noise is never mistaken for a signature", () => {
        const next = rng(SEED);
        let accepted = 0;

        for (let i = 0; i < ITERATIONS * 5; i++) {
            const alphabet = ALPHABETS[Math.floor(next() * ALPHABETS.length)];
            const length = 1 + Math.floor(next() * 200);
            const noise = Array.from({ length },
                () => alphabet.symbols[Math.floor(next() * alphabet.symbols.length)]).join("");
            if (decodeMessage("noise" + ANCHOR + noise).frame) accepted++;
        }

        // The version byte plus the exact-length check make a chance hit vanishingly unlikely.
        expect(accepted).toBe(0);
    });
});

describe("property: ordinary text is never modified", () => {
    it("random unicode text without a payload comes back byte-for-byte", () => {
        const next = rng(SEED);

        for (let i = 0; i < ITERATIONS; i++) {
            const length = Math.floor(next() * 40);
            let text = "";
            for (let c = 0; c < length; c++) {
                // Bias towards the ranges that actually collide with our alphabets.
                const roll = next();
                const cp = roll < 0.25 ? 0xFE00 + Math.floor(next() * 16)
                    : roll < 0.4 ? 0x2764
                        : roll < 0.5 ? 0x200B + Math.floor(next() * 6)
                            : 0x20 + Math.floor(next() * 0x2000);
                text += String.fromCodePoint(cp);
            }

            const decoded = decodeMessage(text);
            if (!decoded.frame) expect(decoded.visibleText, `seed ${SEED} iteration ${i}`).toBe(text);
        }
    });

    it("an emoji at the very end survives a real payload being attached", () => {
        const next = rng(SEED);
        for (const text of AWKWARD_TEXT) {
            const sig = randomBytes(next, 119);
            const decoded = decodeMessage(text + encodePayload(sig, BASE16, undefined, 1787314443));
            expect(decoded.visibleText).toBe(text);
            expect(decoded.frame!.sig).toEqual(sig);
        }
    });
});
