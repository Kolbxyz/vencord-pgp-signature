/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { spawn } from "child_process";
import type { IpcMainInvokeEvent } from "electron";

import { GpgErrorCode, GpgKeyInfo, NativeSignResult } from "./types";

/**
 * Node-side bridge to the local gpg-agent.
 *
 * Signing is delegated to `gpg` rather than done in JS on purpose: it is the only way to use a
 * hardware key (YubiKey touch / PIN), and it keeps the private key out of the renderer entirely.
 * Everything here runs in the Electron main process, so nothing blocks Discord's UI thread.
 */

/**
 * Where gpg usually lives, in probe order. PATH first — a user who installed gpg deliberately
 * almost always has it there — then the default install locations so a fresh Gpg4win or Homebrew
 * install works with no configuration at all.
 */
const GPG_CANDIDATES: Record<string, string[]> = {
    win32: [
        "gpg.exe",
        "C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe",
        "C:\\Program Files\\GnuPG\\bin\\gpg.exe",
        "C:\\Program Files (x86)\\Gpg4win\\bin\\gpg.exe"
    ],
    darwin: ["gpg", "/opt/homebrew/bin/gpg", "/usr/local/bin/gpg", "/usr/bin/gpg"],
    linux: ["gpg", "/usr/bin/gpg", "/usr/local/bin/gpg", "gpg2"]
};

/** Resolved once per session; `null` means "probed, found nothing". */
let resolvedGpg: string | null | undefined;

/** Grace period between SIGTERM and SIGKILL when we give up on a pinentry/touch prompt. */
const KILL_GRACE_MS = 2000;

const SPAWN_TIMEOUT_MS = 10_000;

/**
 * Finds a working gpg. An explicit path from the settings always wins; otherwise the candidates for
 * the platform are probed with `--version` and the first hit is cached for the session.
 */
async function resolveBinary(explicit: string | undefined): Promise<string | null> {
    const override = (explicit ?? "").trim();
    if (override) return override;

    if (resolvedGpg !== undefined) return resolvedGpg;

    for (const candidate of GPG_CANDIDATES[process.platform] ?? GPG_CANDIDATES.linux) {
        const res = await runGpg(candidate, ["--version"], null, SPAWN_TIMEOUT_MS);
        if (!res.spawnFailed && res.code === 0) return resolvedGpg = candidate;
    }

    return resolvedGpg = null;
}

function classifyStderr(stderr: string, spawnFailed: boolean): GpgErrorCode {
    if (spawnFailed) return GpgErrorCode.NoGpg;

    const s = stderr.toLowerCase();
    if (s.includes("card removed") || s.includes("no such device") || s.includes("card error"))
        return GpgErrorCode.CardRemoved;
    if (s.includes("bad pin") || s.includes("wrong pin") || s.includes("blocked"))
        return GpgErrorCode.BadPin;
    if (s.includes("no secret key") || s.includes("no default secret key") || s.includes("unusable secret key"))
        return GpgErrorCode.KeyNotFound;
    if (s.includes("timeout") || s.includes("operation cancelled") || s.includes("cancelled by user"))
        return GpgErrorCode.TouchTimeout;

    return GpgErrorCode.Unknown;
}

interface RunResult {
    stdout: Buffer;
    stderr: string;
    code: number | null;
    spawnFailed: boolean;
    timedOut: boolean;
}

/** Spawns gpg, feeds it `stdin`, and resolves once it exits or the timeout elapses. */
function runGpg(binary: string, args: string[], stdin: Buffer | null, timeoutMs: number): Promise<RunResult> {
    return new Promise(resolve => {
        const chunks: Buffer[] = [];
        let stderr = "";
        let timedOut = false;
        let settled = false;

        const child = spawn(binary, args, { windowsHide: true });

        function finish(r: RunResult) {
            if (settled) return;
            settled = true;
            clearTimeout(killTimer);
            resolve(r);
        }

        const killTimer = setTimeout(() => {
            timedOut = true;
            child.kill("SIGTERM");
            // pinentry can keep the process alive; escalate if SIGTERM is ignored.
            setTimeout(() => child.killed || child.kill("SIGKILL"), KILL_GRACE_MS).unref?.();

            // Resolve now rather than on "close": a stuck child can hold its pipes open long after
            // the signal, and the caller is a message-send handler that must not hang with it.
            finish({ stdout: Buffer.concat(chunks), stderr, code: null, spawnFailed: false, timedOut: true });
        }, timeoutMs);



        child.stdout.on("data", (d: Buffer) => chunks.push(d));
        child.stderr.on("data", (d: Buffer) => { stderr += d.toString("utf8"); });

        child.on("error", err => finish({
            stdout: Buffer.alloc(0),
            stderr: String((err as Error).message ?? err),
            code: null,
            spawnFailed: true,
            timedOut
        }));

        child.on("close", code => finish({
            stdout: Buffer.concat(chunks),
            stderr,
            code,
            spawnFailed: false,
            timedOut
        }));

        if (stdin) {
            // EPIPE is expected if gpg bails out before reading all of stdin — swallow it.
            child.stdin.on("error", () => void 0);
            child.stdin.end(stdin);
        } else {
            child.stdin.end();
        }
    });
}

/**
 * Produces a detached, *binary* (non-armored) signature over `text`.
 * Blocks on the YubiKey touch / PIN prompt for at most `timeoutMs`.
 */
export async function sign(
    _: IpcMainInvokeEvent,
    text: string,
    keyId: string,
    timeoutMs: number,
    gpgPath?: string
): Promise<NativeSignResult> {
    const binary = await resolveBinary(gpgPath);
    if (!binary) {
        return {
            ok: false,
            code: GpgErrorCode.NoGpg,
            error: "gpg not found. Install GnuPG (Gpg4win on Windows) or set its path in the settings."
        };
    }

    const args = [
        "--batch",
        "--no-tty",
        "--yes",
        "--detach-sign",
        "--digest-algo", "SHA512",
        "--output", "-"
    ];
    if (keyId) args.push("--local-user", keyId);

    const res = await runGpg(binary, args, Buffer.from(text, "utf8"), Math.max(1000, timeoutMs));

    if (res.timedOut) {
        return {
            ok: false,
            code: GpgErrorCode.TouchTimeout,
            error: "gpg timed out — the YubiKey was never touched, or the PIN prompt was left open."
        };
    }

    if (res.spawnFailed || res.code !== 0 || res.stdout.length === 0) {
        return {
            ok: false,
            code: classifyStderr(res.stderr, res.spawnFailed),
            error: res.stderr.trim() || `gpg exited with code ${res.code}`
        };
    }

    // Uint8Array does not survive Electron IPC structured cloning cleanly — send a plain array.
    return { ok: true, sig: Array.from(res.stdout) };
}

/** Parses `gpg --list-secret-keys --with-colons` into the keys we can sign with. */
export async function listSecretKeys(_: IpcMainInvokeEvent, gpgPath?: string): Promise<GpgKeyInfo[]> {
    const binary = await resolveBinary(gpgPath);
    if (!binary) return [];

    const res = await runGpg(
        binary,
        ["--batch", "--no-tty", "--with-colons", "--list-secret-keys"],
        null,
        SPAWN_TIMEOUT_MS
    );
    if (res.spawnFailed || res.code !== 0) return [];

    const keys: GpgKeyInfo[] = [];
    let pending: Partial<GpgKeyInfo> | null = null;

    for (const line of res.stdout.toString("utf8").split("\n")) {
        const f = line.split(":");
        switch (f[0]) {
            case "sec":
                if (pending?.fingerprint && pending.uid) keys.push(pending as GpgKeyInfo);
                pending = { algo: pubkeyAlgo(f[3], f[2]), onCard: isOnCard(f[14]) };
                break;
            case "fpr":
                if (pending && !pending.fingerprint) {
                    pending.fingerprint = f[9];
                    pending.keyId = f[9].slice(-16);
                }
                break;
            case "uid":
                if (pending && !pending.uid) pending.uid = unescapeColons(f[9]);
                break;
        }
    }
    if (pending?.fingerprint && pending.uid) keys.push(pending as GpgKeyInfo);

    return keys;
}

/** Returns the gpg the plugin will actually use, or null. Drives the settings UI and the toasts. */
export async function whereIsGpg(_: IpcMainInvokeEvent, gpgPath?: string): Promise<string | null> {
    const binary = await resolveBinary(gpgPath);
    if (!binary) return null;

    const res = await runGpg(binary, ["--version"], null, SPAWN_TIMEOUT_MS);
    return !res.spawnFailed && res.code === 0 ? binary : null;
}

/** Maps gpg's numeric pubkey algorithm id + key length to something readable. */
function pubkeyAlgo(id: string, bits: string): string {
    switch (id) {
        case "1": case "3": return `rsa${bits}`;
        case "17": return "dsa";
        case "18": return "ecdh";
        case "19": return "ecdsa";
        case "22": return "ed25519";
        default: return `algo${id}`;
    }
}

/**
 * Field 15 of a `sec` record says where the secret key lives: "+" available locally, "#" not
 * available, and ">" — or a token serial number — for a key held on a smartcard such as a YubiKey.
 */
function isOnCard(field: string): boolean {
    const v = (field ?? "").trim();
    return v.startsWith(">") || /^[0-9A-Fa-f]{8,}$/.test(v);
}

/** gpg colon output escapes non-ASCII and ':' as \xNN. */
function unescapeColons(s: string): string {
    return (s ?? "").replace(/\\x([0-9a-fA-F]{2})/g, (_m, hex) => String.fromCharCode(parseInt(hex, 16)));
}
