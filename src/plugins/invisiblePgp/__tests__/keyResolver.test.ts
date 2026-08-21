/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { __reset } from "../../../../test/stubs/DataStore";
import {
    armor, crc24, extractEmail, getKeyring, loadKeyring, refineStoredKey, removeKey,
    resolvePublicKey, storeKey, zbase32Sha1
} from "../keyResolver";
import { StoredKey } from "../types";

const KEY_ID = "A1B2C3D4E5F60718";
const FINGERPRINT = "1111222233334444555566" + KEY_ID;
const ARMORED = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZ...\n-----END PGP PUBLIC KEY BLOCK-----";

const ONLINE = { allowNetwork: true, ttlDays: 7 };
const OFFLINE = { allowNetwork: false, ttlDays: 7 };

const stored = (over: Partial<StoredKey> = {}): StoredKey => ({
    armored: ARMORED, uid: "alice@example.org", fingerprint: FINGERPRINT,
    fetchedAt: Date.now(), manual: false, ...over
});

/** A fetch that always fails, recording the URLs it was asked for. */
function failingFetch(urls: string[] = []) {
    return vi.fn(async (u: string) => {
        urls.push(u);
        return { ok: false, headers: new Headers() } as unknown as Response;
    });
}

beforeEach(async () => {
    __reset();
    await loadKeyring();
    for (const id of Object.keys(getKeyring())) await removeKey(id);
    vi.unstubAllGlobals();
});

afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
});

describe("local keyring", () => {
    it("indexes a key by the last 16 hex of its fingerprint", async () => {
        await storeKey(stored());
        expect(getKeyring()).toHaveProperty(KEY_ID);
        expect(await resolvePublicKey(KEY_ID, undefined, OFFLINE)).toMatchObject({ armored: ARMORED });
    });

    it("looks a key up case-insensitively", async () => {
        await storeKey(stored());
        expect(await resolvePublicKey(KEY_ID.toLowerCase(), undefined, OFFLINE)).not.toBeNull();
    });

    it("returns null for a key it has never seen, with the network off", async () => {
        expect(await resolvePublicKey("0000000000000000", undefined, OFFLINE)).toBeNull();
    });

    it("removes a key", async () => {
        await storeKey(stored());
        await removeKey(KEY_ID);
        expect(await resolvePublicKey(KEY_ID, undefined, OFFLINE)).toBeNull();
    });
});

describe("freshness", () => {
    it("serves a key inside its TTL without going online", async () => {
        const fetchSpy = failingFetch();
        vi.stubGlobal("fetch", fetchSpy);
        await storeKey(stored());
        expect(await resolvePublicKey(KEY_ID, undefined, ONLINE)).not.toBeNull();
        expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("treats a hand-imported key as fresh forever", async () => {
        const fetchSpy = failingFetch();
        vi.stubGlobal("fetch", fetchSpy);
        await storeKey(stored({ manual: true, fetchedAt: 0 }));
        expect(await resolvePublicKey(KEY_ID, undefined, ONLINE)).not.toBeNull();
        // A key the user imported by hand is their own trust decision; a refetch could replace it.
        expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("tries to refresh a key past its TTL", async () => {
        const fetchSpy = failingFetch();
        vi.stubGlobal("fetch", fetchSpy);
        await storeKey(stored({ fetchedAt: Date.now() - 30 * 24 * 60 * 60 * 1000 }));
        await resolvePublicKey(KEY_ID, undefined, ONLINE);
        expect(fetchSpy).toHaveBeenCalled();
    });

    it("keeps serving the stale key when the refresh fails — better than no key at all", async () => {
        vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
        await storeKey(stored({ fetchedAt: Date.now() - 30 * 24 * 60 * 60 * 1000 }));
        expect(await resolvePublicKey(KEY_ID, undefined, ONLINE)).toMatchObject({ armored: ARMORED });
    });
});

describe("network behaviour", () => {
    it("does not touch the network when lookups are switched off", async () => {
        const fetchSpy = failingFetch();
        vi.stubGlobal("fetch", fetchSpy);
        await resolvePublicKey("0000000000000000", "alice@example.org", OFFLINE);
        expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("stops retrying a key that just failed, so a busy channel is not a request storm", async () => {
        const fetchSpy = failingFetch();
        vi.stubGlobal("fetch", fetchSpy);

        await resolvePublicKey("0000000000000000", undefined, ONLINE);
        const afterFirst = fetchSpy.mock.calls.length;
        expect(afterFirst).toBeGreaterThan(0);

        for (let i = 0; i < 5; i++) await resolvePublicKey("0000000000000000", undefined, ONLINE);
        expect(fetchSpy.mock.calls.length).toBe(afterFirst);
    });

    it("deduplicates concurrent lookups for the same key", async () => {
        const fetchSpy = vi.fn(async () => {
            await new Promise(r => setTimeout(r, 5));
            return { ok: false, headers: new Headers() } as unknown as Response;
        });
        vi.stubGlobal("fetch", fetchSpy);

        const first = resolvePublicKey("1111111111111111", undefined, ONLINE);
        const rest = Array.from({ length: 7 }, () => resolvePublicKey("1111111111111111", undefined, ONLINE));
        await Promise.all([first, ...rest]);

        // Eight badges rendering at once must not become eight times the requests. One lookup walks
        // the candidate list once; the other seven ride along on the same in-flight promise.
        const oneWalk = 2;
        expect(fetchSpy.mock.calls.length).toBeLessThanOrEqual(oneWalk);
    });

    it("only tries the by-key-id servers when there is no email hint", async () => {
        const urls: string[] = [];
        vi.stubGlobal("fetch", failingFetch(urls));

        await resolvePublicKey("2222222222222222", undefined, ONLINE);
        expect(urls.some(u => u.includes("openpgpkey"))).toBe(false);
        expect(urls.some(u => u.includes("by-keyid"))).toBe(true);
    });

    it("tries WKD first once the uid contains an email", async () => {
        const urls: string[] = [];
        vi.stubGlobal("fetch", failingFetch(urls));

        await resolvePublicKey("3333333333333333", "Alice <alice@example.org>", ONLINE);
        expect(urls[0]).toContain("openpgpkey.example.org");
        expect(urls.some(u => u.includes("keyoxide.org"))).toBe(true);
        // The hashed local part must be resolved, never left as a literal marker.
        expect(urls.some(u => u.includes("{HU:"))).toBe(false);
    });
});

describe("refineStoredKey", () => {
    it("replaces a provisional fingerprint with the real one", async () => {
        await storeKey(stored({ fingerprint: KEY_ID, provisionalFingerprint: true, uid: "" }));
        await refineStoredKey(KEY_ID, FINGERPRINT, "alice@example.org");

        const entry = getKeyring()[KEY_ID];
        expect(entry.fingerprint).toBe(FINGERPRINT);
        expect(entry.provisionalFingerprint).toBe(false);
        expect(entry.uid).toBe("alice@example.org");
    });

    it("leaves the key indexed where it was, so lookups keep working", async () => {
        await storeKey(stored({ fingerprint: KEY_ID, provisionalFingerprint: true }));
        await refineStoredKey(KEY_ID, FINGERPRINT);
        expect(await resolvePublicKey(KEY_ID, undefined, OFFLINE)).not.toBeNull();
    });

    it("does nothing for a key it does not hold", async () => {
        await expect(refineStoredKey("DEADBEEFDEADBEEF", FINGERPRINT)).resolves.toBeUndefined();
    });
});

describe("format helpers", () => {
    it("hashes a WKD local part to the published vector", async () => {
        // The WKD specification's own example: "Joe.Doe", lowercased before hashing.
        expect(await zbase32Sha1("joe.doe")).toBe("iy9q119eutrkn8s1mk4r39qejnbu3n5q");
    });

    it("produces 32 z-base-32 characters for any input", async () => {
        for (const input of ["", "a", "alice", "a.very.long.local.part.indeed"])
            expect(await zbase32Sha1(input)).toMatch(/^[ybndrfg8ejkmcpqxot1uwisza345h769]{32}$/);
    });

    it("computes the RFC 4880 CRC24 initial value for empty input", () => {
        expect(crc24(new Uint8Array(0))).toEqual([0xB7, 0x04, 0xCE]);
    });

    it("computes a CRC24 that changes with the data", () => {
        expect(crc24(new Uint8Array([1, 2, 3]))).not.toEqual(crc24(new Uint8Array([1, 2, 4])));
    });

    it("wraps bytes in armor openpgp.js will accept", () => {
        const out = armor(new Uint8Array([0x99, 0x01, 0x0D]));
        expect(out.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n")).toBe(true);
        expect(out.trimEnd().endsWith("-----END PGP PUBLIC KEY BLOCK-----")).toBe(true);
        expect(out).toMatch(/\n=[A-Za-z0-9+/]{4}\n/); // the CRC24 checksum line
    });

    it("wraps base64 at 64 characters", () => {
        const body = armor(new Uint8Array(200).fill(0x41))
            .split("\n").filter(l => l && !l.startsWith("-") && !l.startsWith("="));
        for (const line of body) expect(line.length).toBeLessThanOrEqual(64);
    });

    it("pulls an email out of the shapes a uid actually takes", () => {
        expect(extractEmail("Alice <alice@example.org>")).toBe("alice@example.org");
        expect(extractEmail("ALICE@EXAMPLE.ORG")).toBe("alice@example.org");
        expect(extractEmail("alice+pgp@sub.example.co.uk")).toBe("alice+pgp@sub.example.co.uk");
    });

    it("returns null for anything that is not an email — a Discord username included", () => {
        for (const uid of [undefined, "", "alice", "alice#1234", "Alice Smith"])
            expect(extractEmail(uid)).toBeNull();
    });
});
