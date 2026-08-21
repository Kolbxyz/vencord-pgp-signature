/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Context binding.
 *
 * Signing the message text alone authenticates *what* was said but not *where*, *when*, or *by
 * whom* — a genuinely signed message can be lifted and reposted in another channel, where it still
 * verifies and reads as if it had been said there. Binding the channel, the author and a timestamp
 * into the signed data closes that.
 *
 * Only the timestamp travels inside the payload (4 bytes). The channel and author ids are read back
 * off the rendered message, so a message moved elsewhere no longer reproduces the signed string.
 */

export interface MessageContext {
    channelId: string;
    authorId: string;
    /** Unix seconds, chosen by the sender's clock. */
    timestamp: number;
}

/** Version tag of the canonical form; a change here invalidates old signatures on purpose. */
const CANONICAL_VERSION = "ipgp1";

/**
 * Builds the exact string that gets signed.
 *
 * Newline-delimited, with the free-form text last: every field before it is digits only, so no
 * user-controlled text can inject a delimiter and shift the field boundaries.
 */
export function canonicalSignedText(ctx: MessageContext, visibleText: string): string {
    return [
        CANONICAL_VERSION,
        ctx.channelId,
        ctx.authorId,
        String(ctx.timestamp),
        visibleText
    ].join("\n");
}

/** Snowflakes are digit strings; anything else means the context is unusable. */
export function isUsableContext(ctx: Partial<MessageContext>): ctx is MessageContext {
    return /^\d+$/.test(ctx.channelId ?? "")
        && /^\d+$/.test(ctx.authorId ?? "")
        && Number.isInteger(ctx.timestamp) && (ctx.timestamp as number) > 0;
}
