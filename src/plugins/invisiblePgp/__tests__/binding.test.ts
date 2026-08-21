/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { describe, expect, it } from "vitest";

import { canonicalSignedText, isUsableContext, MessageContext } from "../binding";
import { FRAME_V1, FRAME_V2 } from "../codec";

const DISCORD: MessageContext = {
    platform: "discord",
    conversationId: "1234567890123456789",
    authorId: "9876543210987654321",
    timestamp: 1787314443
};

const MATRIX: MessageContext = {
    platform: "matrix",
    conversationId: "!AbCdEf:example.org",
    authorId: "@me:example.org",
    timestamp: 1787314443
};

describe("canonical form v2", () => {
    it("lays the fields out exactly as SPEC.md describes", () => {
        expect(canonicalSignedText(MATRIX, "hello")).toBe(
            "ipgp2\n"
            + "6:matrix\n"
            + "19:!AbCdEf:example.org\n"
            + "15:@me:example.org\n"
            + "10:1787314443\n"
            + "0:\n"
            + "hello"
        );
    });

    it("binds the attachment, so a signed image cannot be repointed at another file", () => {
        const withMedia = { ...MATRIX, attachment: "mxc://example.org/AbCdEf" };
        expect(canonicalSignedText(withMedia, "cat.png")).toContain("\n24:mxc://example.org/AbCdEf\n");
        // Swapping the file must change what was signed, even though the caption is identical.
        expect(canonicalSignedText(withMedia, "cat.png"))
            .not.toBe(canonicalSignedText({ ...MATRIX, attachment: "mxc://example.org/Other1" }, "cat.png"));
    });

    it("treats a missing attachment as the empty string", () => {
        expect(canonicalSignedText(MATRIX, "x")).toBe(canonicalSignedText({ ...MATRIX, attachment: "" }, "x"));
    });

    it("counts lengths in UTF-8 bytes, so other languages agree", () => {
        const ctx = { ...MATRIX, conversationId: "!café:example.org" };
        // 17 codepoints, 18 UTF-8 bytes — the é is two.
        expect(canonicalSignedText(ctx, "")).toContain("\n18:!café:example.org\n");
    });

    it("is the default when no frame version is given", () => {
        expect(canonicalSignedText(DISCORD, "x")).toBe(canonicalSignedText(DISCORD, "x", FRAME_V2));
    });

    it("rejects a frame version it does not know", () => {
        expect(() => canonicalSignedText(DISCORD, "x", 0x03)).toThrow(RangeError);
    });
});

describe("canonical form v2 cannot be spoofed by field contents", () => {
    /**
     * The point of length prefixes. Under v1 an id containing a newline could shift every later
     * field, letting one message reproduce another message's signed string. Each case below moves
     * content between fields in a way that v1 would not have distinguished.
     */
    it.each([
        ["newline in the conversation id", { conversationId: "!a:x\n@evil:x" }],
        ["newline in the author id", { authorId: "@a:x\n1787314443" }],
        ["colon-digit prefix that mimics a length header", { conversationId: "5:hello" }],
        ["the whole tag repeated inside an id", { authorId: "ipgp2\n6:matrix" }],
        ["an id that is entirely digits", { conversationId: "1787314443" }]
    ])("%s produces a distinct signed string", (_label, patch) => {
        const spoofed = { ...MATRIX, ...patch } as MessageContext;
        expect(canonicalSignedText(spoofed, "text")).not.toBe(canonicalSignedText(MATRIX, "text"));
    });

    it("keeps two contexts distinct when content simply moves across a boundary", () => {
        const a = canonicalSignedText({ ...MATRIX, conversationId: "!ab", authorId: "@cd" }, "t");
        const b = canonicalSignedText({ ...MATRIX, conversationId: "!a", authorId: "b@cd" }, "t");
        expect(a).not.toBe(b);
    });

    it("separates the platforms, so a Discord signature cannot be replayed on Matrix", () => {
        const shared = { conversationId: "same", authorId: "same", timestamp: 1 };
        expect(canonicalSignedText({ ...shared, platform: "discord" }, "t"))
            .not.toBe(canonicalSignedText({ ...shared, platform: "matrix" }, "t"));
    });

    it("binds text that itself looks like a canonical form", () => {
        const evil = "ipgp2\n6:matrix\n3:!x:\n3:@y:\n1:1\nreal text";
        expect(canonicalSignedText(MATRIX, evil)).not.toBe(canonicalSignedText(MATRIX, "real text"));
        // The text is last and unprefixed, so it appears verbatim and cannot shift a boundary.
        expect(canonicalSignedText(MATRIX, evil).endsWith(evil)).toBe(true);
    });

    it.each(["conversationId", "authorId", "timestamp"] as const)(
        "changes the signed string when %s changes", key => {
            const patched = key === "timestamp"
                ? { ...MATRIX, timestamp: MATRIX.timestamp + 1 }
                : { ...MATRIX, [key]: `${MATRIX[key]}!` };
            expect(canonicalSignedText(patched, "t")).not.toBe(canonicalSignedText(MATRIX, "t"));
        });
});

describe("canonical form v1", () => {
    it("still reproduces the pre-v2 Discord string byte for byte", () => {
        expect(canonicalSignedText(DISCORD, "hello", FRAME_V1))
            .toBe("ipgp1\n1234567890123456789\n9876543210987654321\n1787314443\nhello");
    });

    it("never equals the v2 string for the same context", () => {
        expect(canonicalSignedText(DISCORD, "hello", FRAME_V1))
            .not.toBe(canonicalSignedText(DISCORD, "hello", FRAME_V2));
    });
});

describe("isUsableContext", () => {
    it("accepts a well-formed context on either platform", () => {
        expect(isUsableContext(DISCORD)).toBe(true);
        expect(isUsableContext(MATRIX)).toBe(true);
    });

    it.each([
        ["missing platform", { platform: undefined }],
        ["unknown platform", { platform: "irc" }],
        ["empty conversation id", { conversationId: "" }],
        ["empty author id", { authorId: "" }],
        ["missing conversation id", { conversationId: undefined }],
        ["zero timestamp", { timestamp: 0 }],
        ["negative timestamp", { timestamp: -1 }],
        ["fractional timestamp", { timestamp: 1787314443.5 }],
        ["missing timestamp", { timestamp: undefined }]
    ])("rejects %s", (_label, patch) => {
        expect(isUsableContext({ ...MATRIX, ...patch } as Partial<MessageContext>)).toBe(false);
    });

    it("no longer demands digits, which is what unblocked Matrix ids", () => {
        expect(isUsableContext({ ...MATRIX, conversationId: "!not-digits:example.org" })).toBe(true);
    });
});
