/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * End-to-end verification against real OpenPGP keys.
 *
 * Deliberately not stubbed. The verdicts this module returns are the plugin's entire user-visible
 * security story, and a stubbed openpgp would let a signature that does not actually verify pass
 * the suite. Keys are generated once for the file — Ed25519 keygen is fast enough for that.
 */

import * as openpgp from "openpgp";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { __reset } from "../../../../test/stubs/DataStore";
import { canonicalSignedText, MessageContext } from "../binding";
import { BASE4, encodePayload, FRAME_V1 } from "../codec";
import { getKeyring, removeKey, storeKey } from "../keyResolver";
import { getTrustedSigners, unpinSigner } from "../trustedSigners";
import { VerifyStatus } from "../types";
import { clearCache, ensureVerified, VerifyRequest } from "../verify";

const CHANNEL = "1234567890123456789";
const AUTHOR = "9876543210987654321";
const NOW = 1787314443;
const OPTS = { allowNetwork: false, ttlDays: 7 };

interface Identity {
    publicKey: openpgp.PublicKey;
    privateKey: openpgp.PrivateKey;
    armored: string;
    fingerprint: string;
    keyId: string;
}

async function makeIdentity(name: string): Promise<Identity> {
    const { privateKey, publicKey } = await openpgp.generateKey({
        // openpgp v6's name for a modern Ed25519 signing key.
        type: "curve25519", format: "object",
        userIDs: [{ name, email: `${name}@example.org` }]
    });
    const fingerprint = publicKey.getFingerprint().toUpperCase();
    return {
        publicKey, privateKey,
        armored: publicKey.armor(),
        fingerprint,
        keyId: fingerprint.slice(-16)
    };
}

/** Detached-signs exactly what the plugin signs. */
async function detachedSign(identity: Identity, text: string): Promise<Uint8Array> {
    const signature = await openpgp.sign({
        message: await openpgp.createMessage({ text }),
        signingKeys: identity.privateKey,
        detached: true,
        format: "binary"
    });
    return signature as Uint8Array;
}

let alice: Identity;
let mallory: Identity;

beforeAll(async () => {
    [alice, mallory] = await Promise.all([makeIdentity("alice"), makeIdentity("mallory")]);
}, 30_000);

beforeEach(async () => {
    __reset();
    clearCache();
    for (const id of Object.keys(getKeyring())) await removeKey(id);
    for (const id of Object.keys(getTrustedSigners())) await unpinSigner(id);
    vi.stubGlobal("fetch", vi.fn(async () => {
        throw new Error("no network in tests");
    }));
});

afterEach(() => vi.unstubAllGlobals());

const context = (over: Partial<MessageContext> = {}): MessageContext => ({
    platform: "discord", conversationId: CHANNEL, authorId: AUTHOR, timestamp: NOW, ...over
});

/** Builds a signed message exactly as index.tsx would. */
async function signedMessage(identity: Identity, text: string, ctx = context()): Promise<string> {
    const sig = await detachedSign(identity, canonicalSignedText(ctx, text));
    return text + encodePayload(sig, BASE4, identity.keyId, ctx.timestamp);
}

const request = (content: string, over: Partial<VerifyRequest> = {}): VerifyRequest => ({
    messageId: `msg-${Math.random()}`,
    content,
    channelId: CHANNEL,
    authorId: AUTHOR,
    postedAt: NOW,
    clockToleranceSec: 300,
    autoPin: true,
    username: "alice",
    ...over
});

/** Kicks off verification and waits for the verdict to replace Pending. */
async function verdict(req: VerifyRequest) {
    const first = ensureVerified(req, OPTS);
    if (first.status !== VerifyStatus.Pending) return first;

    for (let i = 0; i < 200; i++) {
        await new Promise(r => setTimeout(r, 5));
        const state = ensureVerified(req, OPTS);
        if (state.status !== VerifyStatus.Pending) return state;
    }
    throw new Error("verification never settled");
}

describe("a genuine signature", () => {
    beforeEach(async () => {
        await storeKey({
            armored: alice.armored, uid: "alice@example.org", fingerprint: alice.fingerprint,
            fetchedAt: Date.now(), manual: true
        });
    });

    it("is Valid, and reports the key that made it", async () => {
        const state = await verdict(request(await signedMessage(alice, "hello there")));
        expect(state.status).toBe(VerifyStatus.Valid);
        expect(state.fingerprint).toBe(alice.fingerprint);
        expect(state.signedAt).toBe(NOW);
    });

    it("is Valid for text full of awkward unicode", async () => {
        for (const text of ["I ❤️ you", "👨‍👩‍👧‍👦", "line\nbreak", "  padded  ", "𝕓𝕠𝕝𝕕"]) {
            const state = await verdict(request(await signedMessage(alice, text)));
            expect(state.status, `text: ${JSON.stringify(text)}`).toBe(VerifyStatus.Valid);
        }
    });

    it("is Valid for an empty message body", async () => {
        expect((await verdict(request(await signedMessage(alice, "")))).status).toBe(VerifyStatus.Valid);
    });

    it("pins the signer on first sight", async () => {
        await verdict(request(await signedMessage(alice, "hello")));
        expect(getTrustedSigners()[AUTHOR].fingerprint).toBe(alice.fingerprint);
    });

    it("does not pin when auto-pinning is off", async () => {
        await verdict(request(await signedMessage(alice, "hello"), { autoPin: false }));
        expect(getTrustedSigners()[AUTHOR]).toBeUndefined();
    });
});

describe("a signature that does not hold up", () => {
    beforeEach(async () => {
        await storeKey({
            armored: alice.armored, uid: "alice@example.org", fingerprint: alice.fingerprint,
            fetchedAt: Date.now(), manual: true
        });
    });

    it("is Invalid when the visible text was edited", async () => {
        const message = await signedMessage(alice, "send money to alice");
        const tampered = message.replace("alice", "mallory");
        expect((await verdict(request(tampered))).status).toBe(VerifyStatus.Invalid);
    });

    it("is Invalid when the message is lifted into another channel", async () => {
        const message = await signedMessage(alice, "hello");
        const state = await verdict(request(message, { channelId: "1111111111111111111" }));
        expect(state.status).toBe(VerifyStatus.Invalid);
    });

    it("is Invalid when the message is attributed to another author", async () => {
        const message = await signedMessage(alice, "hello");
        const state = await verdict(request(message, { authorId: "2222222222222222222" }));
        expect(state.status).toBe(VerifyStatus.Invalid);
    });

    it("is Invalid when the header key id contradicts the signature packet", async () => {
        // The header hint drives key lookup, so a mismatch is an attempt to steer the verifier at
        // a key other than the one that signed. It must not be quietly ignored.
        const ctx = context();
        const sig = await detachedSign(alice, canonicalSignedText(ctx, "hello"));
        const message = "hello" + encodePayload(sig, BASE4, mallory.keyId, ctx.timestamp);

        const state = await verdict(request(message));
        expect(state.status).toBe(VerifyStatus.Invalid);
        expect(state.reason).toMatch(/does not match/i);
    });

    it("is Replayed when the signing time is far from the posting time", async () => {
        const message = await signedMessage(alice, "hello");
        const state = await verdict(request(message, { postedAt: NOW + 4000 }));
        expect(state.status).toBe(VerifyStatus.Replayed);
    });

    it("accepts drift inside the tolerance", async () => {
        const message = await signedMessage(alice, "hello");
        const state = await verdict(request(message, { postedAt: NOW + 120 }));
        expect(state.status).toBe(VerifyStatus.Valid);
    });

    it("treats drift as symmetric", async () => {
        const message = await signedMessage(alice, "hello");
        expect((await verdict(request(message, { postedAt: NOW - 4000 }))).status)
            .toBe(VerifyStatus.Replayed);
    });
});

describe("key trouble", () => {
    it("is UnknownKey when the signing key cannot be resolved", async () => {
        const state = await verdict(request(await signedMessage(alice, "hello")));
        expect(state.status).toBe(VerifyStatus.UnknownKey);
    });

    it("is KeyChanged when an enrolled account signs with a different key", async () => {
        await storeKey({
            armored: alice.armored, uid: "alice@example.org", fingerprint: alice.fingerprint,
            fetchedAt: Date.now(), manual: true
        });
        await verdict(request(await signedMessage(alice, "first")));

        await storeKey({
            armored: mallory.armored, uid: "mallory@example.org", fingerprint: mallory.fingerprint,
            fetchedAt: Date.now(), manual: true
        });
        const state = await verdict(request(await signedMessage(mallory, "second")));

        expect(state.status).toBe(VerifyStatus.KeyChanged);
        expect(state.pinnedFingerprint).toBe(alice.fingerprint);
    });

    it("is Error for a payload that is not a signature packet at all", async () => {
        const junk = "hello" + encodePayload(new Uint8Array(80).fill(0x42), BASE4, alice.keyId, NOW);
        expect((await verdict(request(junk))).status).toBe(VerifyStatus.Error);
    });
});

describe("messages with no signature", () => {
    it("is Unsigned for an ordinary message from an unknown account", () => {
        expect(ensureVerified(request("just talking"), OPTS).status).toBe(VerifyStatus.Unsigned);
    });

    it("is Unsigned for text that merely contains an emoji", () => {
        expect(ensureVerified(request("I ❤️ you"), OPTS).status).toBe(VerifyStatus.Unsigned);
    });

    it("is MissingSignature once the account is known to sign", async () => {
        await storeKey({
            armored: alice.armored, uid: "alice@example.org", fingerprint: alice.fingerprint,
            fetchedAt: Date.now(), manual: true
        });
        await verdict(request(await signedMessage(alice, "signed")));

        const state = ensureVerified(request("suddenly unsigned"), OPTS);
        expect(state.status).toBe(VerifyStatus.MissingSignature);
        expect(state.pinnedFingerprint).toBe(alice.fingerprint);
    });
});

describe("legacy v1 messages stay verifiable", () => {
    it("verifies a base4 v1 payload against the ipgp1 canonical form", async () => {
        await storeKey({
            armored: alice.armored, uid: "alice@example.org", fingerprint: alice.fingerprint,
            fetchedAt: Date.now(), manual: true
        });

        const ctx = context();
        const text = "an old signed message";
        const v1Text = canonicalSignedText(ctx, text, FRAME_V1);
        const sig = await detachedSign(alice, v1Text);

        // Rebuild a v1 frame by hand: magic | flags | keyId(8) | ts(4) | sigLen(2) | sig.
        const frame = new Uint8Array(16 + sig.length);
        frame[0] = FRAME_V1;
        frame[1] = 0b11;
        for (let i = 0; i < 8; i++) frame[2 + i] = parseInt(alice.keyId.slice(i * 2, i * 2 + 2), 16);
        const view = new DataView(frame.buffer);
        view.setUint32(10, ctx.timestamp);
        view.setUint16(14, sig.length);
        frame.set(sig, 16);

        const base4 = ["​", "‌", "‍", "⁠"];
        let run = "";
        for (const byte of frame)
            for (let shift = 6; shift >= 0; shift -= 2) run += base4[(byte >> shift) & 0b11];

        expect((await verdict(request(text + run))).status).toBe(VerifyStatus.Valid);
    });
});

describe("caching", () => {
    it("does not start a second verification for the same message", async () => {
        await storeKey({
            armored: alice.armored, uid: "alice@example.org", fingerprint: alice.fingerprint,
            fetchedAt: Date.now(), manual: true
        });
        const req = request(await signedMessage(alice, "hello"));

        await verdict(req);
        // A settled verdict is served straight from the cache, never re-entering Pending.
        expect(ensureVerified(req, OPTS).status).toBe(VerifyStatus.Valid);
    });
});
