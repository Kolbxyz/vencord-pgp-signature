/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Context binding.
 *
 * Signing the message text alone authenticates *what* was said but not *where*, *when* or *by
 * whom* — a genuinely signed message can be lifted and reposted in another conversation, where it
 * still verifies and reads as if it had been said there. Binding the conversation, the author and
 * a timestamp into the signed data closes that.
 *
 * Only the timestamp travels inside the payload. The conversation and author ids are read back off
 * the rendered message, so a message moved elsewhere no longer reproduces the signed string.
 */

import { FRAME_V1, FRAME_V2 } from "./codec";

/** Platforms that can produce a binding. The tag is part of the signed data. */
export type Platform = "discord" | "matrix";

export interface MessageContext {
    platform: Platform;
    /** Channel id on Discord, room id on Matrix. */
    conversationId: string;
    /** User id on Discord, MXID on Matrix. */
    authorId: string;
    /** Unix seconds, chosen by the sender's clock. */
    timestamp: number;
    /**
     * Reference to the media this message carries, or "" when it carries none.
     *
     * Without this, a signature over an image message covers only its filename, so a captured
     * signed message could keep its signature while pointing at a different file. On Matrix this
     * is the `mxc://` URI (or the encrypted `file.url`); Discord has no equivalent yet, so it
     * signs the empty string.
     */
    attachment?: string;
}

/**
 * v1: `ipgp1\n<channelId>\n<authorId>\n<timestamp>\n<text>`, Discord only.
 *
 * Safe there only because every field before the text was validated as digits-only, so nothing
 * user-controlled could contain the `\n` delimiter. That assumption does not survive contact with
 * Matrix, where ids look like `!room:server` and `@user:server`.
 */
const V1_TAG = "ipgp1";

/**
 * v2: length-prefixed, so no field can be confused with another regardless of its contents.
 *
 *   ipgp2\n
 *   <byteLen>:<platform>\n
 *   <byteLen>:<conversationId>\n
 *   <byteLen>:<authorId>\n
 *   <byteLen>:<timestamp>\n
 *   <byteLen>:<attachment>\n
 *   <visibleText>
 *
 * Lengths are UTF-8 byte counts so that implementations in different languages agree exactly.
 * The free-form text stays last and unprefixed, where it cannot shift any boundary.
 */
const V2_TAG = "ipgp2";

const utf8 = new TextEncoder();

function field(value: string): string {
    return `${utf8.encode(value).length}:${value}\n`;
}

/** Builds the exact string that gets signed, in the form matching the given frame version. */
export function canonicalSignedText(
    ctx: MessageContext,
    visibleText: string,
    frameVersion: number = FRAME_V2
): string {
    if (frameVersion === FRAME_V1) {
        // Reproduced verbatim so signatures made before v2 keep verifying. Never emitted anymore.
        return [V1_TAG, ctx.conversationId, ctx.authorId, String(ctx.timestamp), visibleText].join("\n");
    }
    if (frameVersion !== FRAME_V2) throw new RangeError(`Unknown frame version: ${frameVersion}`);

    return V2_TAG + "\n"
        + field(ctx.platform)
        + field(ctx.conversationId)
        + field(ctx.authorId)
        + field(String(ctx.timestamp))
        + field(ctx.attachment ?? "")
        + visibleText;
}

const PLATFORMS: readonly string[] = ["discord", "matrix"];

/**
 * A context is usable when every bound field is present and non-empty.
 *
 * v2 needs no character restrictions — length prefixes make the encoding unambiguous for any
 * content — but an empty id would still bind the message to nothing in particular, so it is
 * rejected rather than signed over.
 */
export function isUsableContext(ctx: Partial<MessageContext>): ctx is MessageContext {
    return PLATFORMS.includes(ctx.platform ?? "")
        && typeof ctx.conversationId === "string" && ctx.conversationId.length > 0
        && typeof ctx.authorId === "string" && ctx.authorId.length > 0
        && Number.isInteger(ctx.timestamp) && (ctx.timestamp as number) > 0;
}
