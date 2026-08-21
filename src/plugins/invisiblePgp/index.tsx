/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import "./styles.css";

import { addPreSendListener, removePreSendListener, MessageSendListener } from "@api/MessageEvents";
import { Devs } from "@utils/constants";
import definePlugin from "@utils/types";
import { showToast, Toasts, UserStore } from "@webpack/common";
import type { Message } from "discord-types/general";

import { canonicalSignedText, isUsableContext } from "./binding";
import { SignatureBadge } from "./components/SignatureBadge";
import { loadKeyring } from "./keyResolver";
import { loadTrustedSigners } from "./trustedSigners";
import { isDesktop, Native } from "./native.bridge";
import { settings } from "./settings";
import { GpgErrorCode } from "./types";
import { clearCache, invalidate } from "./verify";
import {
    attachPayload,
    encodeSignatureToZeroWidth,
    hasZeroWidthPayload,
    PayloadTooLongError
} from "./zeroWidth";

const ERROR_MESSAGES: Record<GpgErrorCode, string> = {
    [GpgErrorCode.NoGpg]: "gpg not found. Install GnuPG or fix its path in the settings.",
    [GpgErrorCode.KeyNotFound]: "The configured signing key is not in your keyring.",
    [GpgErrorCode.CardRemoved]: "YubiKey missing, or unplugged while signing.",
    [GpgErrorCode.BadPin]: "Wrong PIN, or the card is blocked.",
    [GpgErrorCode.TouchTimeout]: "Timed out: the YubiKey was not touched in time.",
    [GpgErrorCode.Unknown]: "gpg failed."
};

function fail(reason: string): { cancel: boolean; } {
    const failClosed = settings.store.failClosed;
    showToast(
        failClosed ? `Cannot sign — message not sent. ${reason}` : `Message sent UNSIGNED. ${reason}`,
        Toasts.Type.FAILURE
    );
    return { cancel: failClosed };
}

const onBeforeSend: MessageSendListener = async (channelId, msg) => {
    if (!settings.store.signOutgoing) return;

    const content = msg.content ?? "";
    if (!content.trim()) return;

    // Never sign a message that already carries a payload (edits, resends, forwarded text).
    if (hasZeroWidthPayload(content)) return;

    const keyId = settings.store.signingKeyId;
    if (!keyId) return fail("No signing key selected.");

    Toasts.show({
        message: "Signing — touch your YubiKey if it is blinking…",
        id: Toasts.genId(),
        type: Toasts.Type.MESSAGE,
        options: { duration: settings.store.touchTimeoutMs, position: Toasts.Position.BOTTOM }
    });

    // Bind the signature to where and when it is being sent, so it cannot be lifted into another
    // channel and still verify. The author id is our own — the receiver checks it against the
    // rendered message, which is why it does not need to travel inside the payload.
    const ctx = {
        channelId,
        authorId: UserStore.getCurrentUser()?.id ?? "",
        timestamp: Math.floor(Date.now() / 1000)
    };
    if (!isUsableContext(ctx)) return fail("Could not determine the channel or your own user id.");

    let signing: Awaited<ReturnType<typeof Native.sign>>;
    try {
        // Awaiting here does not block the UI thread: gpg runs in the main process.
        signing = await Native.sign(
            canonicalSignedText(ctx, content),
            keyId,
            settings.store.touchTimeoutMs,
            settings.store.gpgPath
        );
    } finally {
        Toasts.pop();
    }

    if (!signing.ok)
        return fail(`${ERROR_MESSAGES[signing.code]} ${signing.error}`.trim());

    try {
        const payload = encodeSignatureToZeroWidth(new Uint8Array(signing.sig), keyId.slice(-16), ctx.timestamp);
        msg.content = attachPayload(content, payload);
    } catch (e) {
        if (e instanceof PayloadTooLongError)
            return fail(`Too long once signed: remove ${e.overflow} characters.`);
        return fail(String((e as Error).message ?? e));
    }
};


/**
 * Everything the plugin can work out on its own, so a fresh install needs no settings trip:
 * gpg is located by probing, and the signing key is picked when the choice is unambiguous —
 * a key living on a smartcard wins, since that is the one the user plugged in on purpose.
 */
async function autoConfigure(): Promise<void> {
    if (!isDesktop) {
        if (settings.store.signOutgoing)
            showToast("InvisiblePGP: signing needs Vencord Desktop. Verification still works.", Toasts.Type.MESSAGE);
        return;
    }

    const gpg = await Native.whereIsGpg(settings.store.gpgPath);
    if (!gpg) {
        if (settings.store.signOutgoing)
            showToast("InvisiblePGP: gpg not found, messages will go out unsigned.", Toasts.Type.FAILURE);
        return;
    }

    if (settings.store.signingKeyId) return;

    const keys = await Native.listSecretKeys(settings.store.gpgPath);
    const chosen = keys.find(k => k.onCard) ?? (keys.length === 1 ? keys[0] : undefined);
    if (!chosen) return;

    settings.store.signingKeyId = chosen.keyId;
    showToast(`InvisiblePGP: signing key ${chosen.uid}${chosen.onCard ? " (smartcard)" : ""}`, Toasts.Type.SUCCESS);
}

export default definePlugin({
    name: "InvisiblePGP",
    description:
        "Signs your messages with a detached OpenPGP signature hidden in invisible characters, and "
        + "verifies everyone else's. Signing is delegated to gpg-agent, so hardware keys work.",
    authors: [Devs.Ven],
    dependencies: ["MessageEventsAPI"],
    settings,

    start() {
        void loadKeyring();
        void loadTrustedSigners();
        addPreSendListener(onBeforeSend);
        void autoConfigure();
    },

    stop() {
        removePreSendListener(onBeforeSend);
        clearCache();
    },

    flux: {
        // An edit rewrites the signed text, so the previous verdict is stale.
        MESSAGE_UPDATE({ message }: { message: Message; }) {
            if (message?.id) invalidate(message.id);
        }
    },

    /**
     * Rendered inline next to the message. Vencord calls this for every message it renders, so the
     * component itself owns the caching — see verify.ts.
     */
    renderMessageDecoration: (props: { message: Message; }) => <SignatureBadge message={props.message} />
});
