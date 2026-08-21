/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { GpgErrorCode, GpgKeyInfo, NativeSignResult } from "./types";

/**
 * Renderer-side view of `native.ts`.
 *
 * Vencord exposes a plugin's native.ts under `VencordNative.pluginHelpers.<PluginName>`, but only in
 * the desktop app. On web (and in the browser extension) the helper is simply absent, so every call
 * degrades into a NoGpg result instead of throwing somewhere deep in a send handler.
 */

type NativeApi = {
    sign(text: string, keyId: string, timeoutMs: number, gpgPath?: string): Promise<NativeSignResult>;
    listSecretKeys(gpgPath?: string): Promise<GpgKeyInfo[]>;
    whereIsGpg(gpgPath?: string): Promise<string | null>;
};

const helpers = (window as any).VencordNative?.pluginHelpers?.InvisiblePGP as NativeApi | undefined;

export const isDesktop = Boolean(helpers);

export const Native: NativeApi = {
    sign: (text, keyId, timeoutMs, gpgPath) =>
        helpers
            ? helpers.sign(text, keyId, timeoutMs, gpgPath)
            : Promise.resolve<NativeSignResult>({
                ok: false,
                code: GpgErrorCode.NoGpg,
                error: "Signing needs Vencord Desktop: a browser cannot talk to gpg-agent."
            }),

    listSecretKeys: gpgPath => helpers ? helpers.listSecretKeys(gpgPath) : Promise.resolve([]),

    whereIsGpg: gpgPath => helpers ? helpers.whereIsGpg(gpgPath) : Promise.resolve(null)
};
