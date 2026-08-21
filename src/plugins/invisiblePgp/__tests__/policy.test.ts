/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { beforeEach, describe, expect, it } from "vitest";

import { __reset } from "../../../../test/stubs/DataStore";
import {
    getSignedChannels, isChannelSigned, loadChannelPolicy, setChannelSigned, toggleChannelSigned
} from "../channelPolicy";
import { findKeyAttachment, findPublicKeyBlock, MAX_KEY_BYTES } from "../publicKeyDetection";

beforeEach(async () => {
    __reset();
    await loadChannelPolicy();
    for (const id of Object.keys(getSignedChannels())) await setChannelSigned(id, false);
});

describe("channel policy", () => {
    it("signs nowhere until a channel is switched on", () => {
        expect(isChannelSigned("123")).toBe(false);
        expect(getSignedChannels()).toEqual({});
    });

    it("switches a single channel on without touching the others", async () => {
        await setChannelSigned("123", true);
        expect(isChannelSigned("123")).toBe(true);
        expect(isChannelSigned("456")).toBe(false);
    });

    it("switches a channel back off", async () => {
        await setChannelSigned("123", true);
        await setChannelSigned("123", false);
        expect(isChannelSigned("123")).toBe(false);
        expect(getSignedChannels()).not.toHaveProperty("123");
    });

    it("toggles and reports the new state", async () => {
        expect(await toggleChannelSigned("123")).toBe(true);
        expect(isChannelSigned("123")).toBe(true);
        expect(await toggleChannelSigned("123")).toBe(false);
        expect(isChannelSigned("123")).toBe(false);
    });

    it("records when signing was switched on", async () => {
        const before = Date.now();
        await setChannelSigned("123", true);
        expect(getSignedChannels()["123"]).toBeGreaterThanOrEqual(before);
    });

    it("answers synchronously, because the send listener cannot await", () => {
        // Guards the invariant, not the value: a Promise here would silently make every channel
        // look signed to `if (isChannelSigned(...))`.
        expect(isChannelSigned("123")).not.toBeInstanceOf(Promise);
    });
});

describe("inline public key detection", () => {
    const KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZ...\n-----END PGP PUBLIC KEY BLOCK-----";

    it("extracts a key surrounded by chatter", () => {
        expect(findPublicKeyBlock(`here you go\n${KEY}\nlet me know`)).toBe(KEY);
    });

    it("returns null when there is no key", () => {
        for (const text of [undefined, "", "just talking", "-----BEGIN PGP MESSAGE-----"])
            expect(findPublicKeyBlock(text)).toBeNull();
    });

    it("returns null for a block that begins but never ends", () => {
        expect(findPublicKeyBlock("-----BEGIN PGP PUBLIC KEY BLOCK-----\nmDMEZ...")).toBeNull();
    });

    it("does not treat a private key block as a public one", () => {
        expect(findPublicKeyBlock("-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK-----"))
            .toBeNull();
    });

    it("takes the first complete block when there are several", () => {
        expect(findPublicKeyBlock(`${KEY}\n${KEY}`)).toBe(KEY);
    });
});

describe("key attachment detection", () => {
    const ok = { filename: "key.asc", url: "https://cdn.example/key.asc", size: 4096 };

    it("accepts each recognised extension", () => {
        for (const ext of [".asc", ".gpg", ".pgp", ".key"])
            expect(findKeyAttachment([{ ...ok, filename: `mykey${ext}` }])).not.toBeNull();
    });

    it("matches the extension case-insensitively", () => {
        expect(findKeyAttachment([{ ...ok, filename: "KEY.ASC" }])).not.toBeNull();
    });

    it("ignores files that are not keys", () => {
        expect(findKeyAttachment([{ ...ok, filename: "holiday.png" }])).toBeNull();
    });

    it("refuses anything above the size cap, so a huge file is never fetched", () => {
        expect(findKeyAttachment([{ ...ok, size: MAX_KEY_BYTES + 1 }])).toBeNull();
        expect(findKeyAttachment([{ ...ok, size: MAX_KEY_BYTES }])).not.toBeNull();
    });

    it("refuses an attachment with no url", () => {
        expect(findKeyAttachment([{ filename: "key.asc", size: 10 }])).toBeNull();
    });

    it("handles an empty or missing attachment list", () => {
        expect(findKeyAttachment([])).toBeNull();
        expect(findKeyAttachment(undefined)).toBeNull();
    });

    it("skips past unsuitable attachments to find a usable one", () => {
        expect(findKeyAttachment([{ filename: "a.png" }, { ...ok, size: MAX_KEY_BYTES + 1 }, ok])).toBe(ok);
    });
});
