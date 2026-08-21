/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Trust-on-first-use is the plugin's weakest link and its most important one: everything the badge
 * claims about "this account normally signs" rests on these four outcomes being right.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

import { __reset } from "../../../../test/stubs/DataStore";
import {
    getTrustedSigner, getTrustedSigners, isTracked, loadTrustedSigners, pinSigner, recordVerified,
    unpinSigner
} from "../trustedSigners";

const USER = "9876543210987654321";
const FP_A = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555";
const FP_B = "FFFF9999EEEE8888DDDD7777CCCC6666BBBB5555";

const seen = (fingerprint: string, autoPin = true) =>
    recordVerified(USER, "alice", fingerprint, fingerprint.slice(-16), "alice@example.org", autoPin);

beforeEach(async () => {
    __reset();
    await loadTrustedSigners();
    for (const id of Object.keys(getTrustedSigners())) await unpinSigner(id);
});

describe("first sight", () => {
    it("pins the key when auto-pinning is on", async () => {
        expect(await seen(FP_A)).toBe("pinned");

        const signer = getTrustedSigner(USER)!;
        expect(signer.fingerprint).toBe(FP_A);
        expect(signer.username).toBe("alice");
        expect(signer.uid).toBe("alice@example.org");
        expect(signer.source).toBe("detected");
        expect(isTracked(USER)).toBe(true);
    });

    it("pins nothing when auto-pinning is off", async () => {
        expect(await seen(FP_A, false)).toBe("ignored");
        expect(isTracked(USER)).toBe(false);
    });
});

describe("the same key again", () => {
    it("refreshes rather than re-pinning", async () => {
        await seen(FP_A);
        expect(await seen(FP_A)).toBe("refreshed");
    });

    it("moves lastSeenAt forward but leaves addedAt alone", async () => {
        vi.useFakeTimers();
        try {
            vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
            await seen(FP_A);
            const { addedAt, lastSeenAt } = getTrustedSigner(USER)!;

            vi.setSystemTime(new Date("2026-06-01T00:00:00Z"));
            await seen(FP_A);
            const after = getTrustedSigner(USER)!;

            expect(after.addedAt).toBe(addedAt);
            expect(after.lastSeenAt).toBeGreaterThan(lastSeenAt);
        } finally {
            vi.useRealTimers();
        }
    });

    it("follows a username change, so the entry stays readable after a rename", async () => {
        await seen(FP_A);
        await recordVerified(USER, "alice_renamed", FP_A, FP_A.slice(-16), "alice@example.org", true);
        expect(getTrustedSigner(USER)!.username).toBe("alice_renamed");
    });
});

describe("a different key", () => {
    it("is reported as a mismatch, not accepted", async () => {
        await seen(FP_A);
        expect(await seen(FP_B)).toBe("mismatch");
    });

    it("leaves the originally pinned key in place", async () => {
        await seen(FP_A);
        await seen(FP_B);
        expect(getTrustedSigner(USER)!.fingerprint).toBe(FP_A);
    });

    it("cannot take over even with auto-pinning on — that is the whole point", async () => {
        await seen(FP_A);
        for (let i = 0; i < 5; i++) expect(await seen(FP_B)).toBe("mismatch");
        expect(getTrustedSigner(USER)!.fingerprint).toBe(FP_A);
    });

    it("compares full fingerprints, not the 16-hex key id", async () => {
        await seen(FP_A);
        // Same trailing 16 hex, different key. Comparing key ids would wrongly say "refreshed".
        const collision = `0000000000000000000000${FP_A.slice(-16)}`.slice(-40);
        expect(await seen(collision)).toBe("mismatch");
    });
});

describe("manual pins", () => {
    it("are not overwritten by trust-on-first-use", async () => {
        await pinSigner(USER, {
            fingerprint: FP_A, keyId: FP_A.slice(-16), uid: "alice@example.org",
            username: "alice", addedAt: Date.now(), lastSeenAt: Date.now(), source: "manual"
        });
        expect(await seen(FP_B)).toBe("mismatch");
        expect(getTrustedSigner(USER)!.source).toBe("manual");
    });

    it("still refresh on a matching signature, keeping the manual marking", async () => {
        await pinSigner(USER, {
            fingerprint: FP_A, keyId: FP_A.slice(-16), uid: "alice@example.org",
            username: "alice", addedAt: Date.now(), lastSeenAt: Date.now(), source: "manual"
        });
        expect(await seen(FP_A)).toBe("refreshed");
        expect(getTrustedSigner(USER)!.source).toBe("manual");
    });
});

describe("unpinning", () => {
    it("forgets the account entirely and allows a fresh pin", async () => {
        await seen(FP_A);
        await unpinSigner(USER);
        expect(isTracked(USER)).toBe(false);
        expect(getTrustedSigner(USER)).toBeUndefined();
        expect(await seen(FP_B)).toBe("pinned");
    });
});

describe("isolation between accounts", () => {
    it("keeps one account's key out of another's", async () => {
        await seen(FP_A);
        expect(await recordVerified("111", "bob", FP_B, FP_B.slice(-16), "bob@example.org", true)).toBe("pinned");
        expect(getTrustedSigner(USER)!.fingerprint).toBe(FP_A);
        expect(getTrustedSigner("111")!.fingerprint).toBe(FP_B);
    });
});
