/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import * as DataStore from "@api/DataStore";

/**
 * Where signing is switched on.
 *
 * Signing is off everywhere by default and enabled one channel at a time, on purpose: a signature is
 * permanent, transferable proof of what you wrote, so it belongs on the conversations you chose, not
 * on everything you type. See the README's section on non-repudiation.
 */

const STORE_KEY = "InvisiblePGP_signedChannels";

/** channelId -> when it was switched on. Mirrored in memory so the send path stays synchronous. */
let enabled: Record<string, number> = {};
let loaded = false;

export async function loadChannelPolicy(): Promise<void> {
    if (loaded) return;
    enabled = (await DataStore.get<Record<string, number>>(STORE_KEY)) ?? {};
    loaded = true;
}

export function getSignedChannels(): Record<string, number> {
    return enabled;
}

/** Synchronous by design: the send listener must decide without awaiting. */
export function isChannelSigned(channelId: string): boolean {
    return Boolean(enabled[channelId]);
}

async function persist(): Promise<void> {
    await DataStore.set(STORE_KEY, enabled);
}

export async function setChannelSigned(channelId: string, on: boolean): Promise<void> {
    await loadChannelPolicy();
    if (on) enabled[channelId] = Date.now();
    else delete enabled[channelId];
    await persist();
}

export async function toggleChannelSigned(channelId: string): Promise<boolean> {
    const next = !isChannelSigned(channelId);
    await setChannelSigned(channelId, next);
    return next;
}
