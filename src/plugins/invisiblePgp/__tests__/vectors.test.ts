/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * The TypeScript half of the cross-language contract.
 *
 * `synapse_module/tests/test_vectors.py` runs the same file through the Python implementation. If
 * one side drifts, exactly one of the two suites goes red — which is the whole reason the vectors
 * are a committed artefact rather than something each side generates for itself.
 */

import { describe, expect, it } from "vitest";

import vectors from "../../../../tests/vectors.json";
import { canonicalSignedText, MessageContext } from "../binding";
import { decodeMessage } from "../codec";

const hex = (bytes: Uint8Array) => [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");

describe("codec vectors", () => {
    it("covers every alphabet and both frame versions", () => {
        const alphabets = new Set(vectors.codec.map(v => v.alphabet));
        expect(alphabets).toContain("base4");
        expect(alphabets).toContain("base16");
        expect(alphabets).toContain("base256");
        expect(vectors.codec.some(v => v.name.includes("legacy-v1"))).toBe(true);
        expect(vectors.codec.some(v => v.expect === null)).toBe(true);
    });

    it.each(vectors.codec)("$name — $why", vector => {
        const decoded = decodeMessage(vector.message);

        if (vector.expect === null) {
            expect(decoded.frame).toBeNull();
            // A rejected payload must leave the message exactly as it arrived.
            expect(decoded.visibleText).toBe(vector.message);
            return;
        }

        expect(decoded.frame).not.toBeNull();
        expect(decoded.visibleText).toBe(vector.expect.visibleText);
        expect(hex(decoded.frame!.sig)).toBe(vector.expect.sigHex);
        expect(decoded.frame!.keyId ?? null).toBe(vector.expect.keyId);
        expect(decoded.frame!.timestamp ?? null).toBe(vector.expect.timestamp);
        expect(decoded.alphabet!.name).toBe(vector.alphabet);
    });
});

describe("binding vectors", () => {
    it.each(vectors.binding)("$name — $why", vector => {
        expect(canonicalSignedText(
            vector.context as MessageContext,
            vector.visibleText,
            vector.frameVersion
        )).toBe(vector.canonical);
    });
});
