/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Spotting someone handing you their public key.
 *
 * This is the one thing the plugin reacts to on its own. Sending a public key is an unambiguous
 * "I do PGP, here is mine" — and it is the moment where switching signing on for that conversation
 * is what the user would have done anyway.
 */

const ARMOR_BEGIN = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
const ARMOR_END = "-----END PGP PUBLIC KEY BLOCK-----";

const KEY_EXTENSIONS = [".asc", ".gpg", ".pgp", ".key"];

/** Refuse to download anything larger than this: a public key is a few kilobytes. */
export const MAX_KEY_BYTES = 256 * 1024;

export interface AttachmentLike {
    filename?: string;
    url?: string;
    size?: number;
    content_type?: string;
}

/** Extracts an inline armored public key block, or null. */
export function findPublicKeyBlock(content: string | undefined): string | null {
    if (!content) return null;

    const start = content.indexOf(ARMOR_BEGIN);
    if (start === -1) return null;

    const end = content.indexOf(ARMOR_END, start);
    if (end === -1) return null;

    return content.slice(start, end + ARMOR_END.length);
}

/** Picks the first attachment that looks like a key file and is small enough to fetch. */
export function findKeyAttachment(attachments: AttachmentLike[] | undefined): AttachmentLike | null {
    for (const a of attachments ?? []) {
        const name = (a.filename ?? "").toLowerCase();
        if (!KEY_EXTENSIONS.some(ext => name.endsWith(ext))) continue;
        if ((a.size ?? 0) > MAX_KEY_BYTES) continue;
        if (!a.url) continue;
        return a;
    }
    return null;
}

/** Downloads an attachment and returns it only if it really is an armored public key. */
export async function fetchArmoredKey(url: string): Promise<string | null> {
    try {
        const res = await fetch(url);
        if (!res.ok) return null;

        const len = Number(res.headers.get("content-length") ?? 0);
        if (len > MAX_KEY_BYTES) return null;

        const text = (await res.text()).slice(0, MAX_KEY_BYTES);
        return findPublicKeyBlock(text);
    } catch {
        return null;
    }
}
