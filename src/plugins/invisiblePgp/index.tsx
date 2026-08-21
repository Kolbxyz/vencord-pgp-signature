/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import "./styles.css";

import { addContextMenuPatch, NavContextMenuPatchCallback, removeContextMenuPatch } from "@api/ContextMenu";
import { addMessagePreSendListener, removeMessagePreSendListener, MessageSendListener } from "@api/MessageEvents";
import definePlugin from "@utils/types";
import { Menu, MessageStore, showToast, Toasts, UserStore } from "@webpack/common";
import type { Message } from "discord-types/general";

import { canonicalSignedText, isUsableContext } from "./binding";
import { isChannelSigned, loadChannelPolicy, toggleChannelSigned } from "./channelPolicy";
import {
    attachPayload,
    BASE4,
    decodeMessage,
    encodePayload,
    hasPayload,
    PayloadTooLongError
} from "./codec";
import { PublicKeyOffer } from "./components/PublicKeyOffer";
import { SignatureBadge } from "./components/SignatureBadge";
import { loadKeyring } from "./keyResolver";
import { loadTrustedSigners } from "./trustedSigners";
import { isDesktop, Native } from "./native.bridge";
import { settings } from "./settings";
import { GpgErrorCode } from "./types";
import { clearCache, invalidate } from "./verify";

/**
 * Not in Vencord's `Devs` table — this plugin is maintained outside the main repo, so it carries
 * its own author record. Replace `id` with the maintainer's Discord id before upstreaming.
 */
const AUTHOR = { name: "kolbxyz", id: 0n } as const;

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

const onBeforeSend: MessageSendListener = async (channelId, msg, _options, props) => {
    // Off everywhere until this channel was explicitly switched on.
    if (!isChannelSigned(channelId)) return;

    const content = msg.content ?? "";
    const hasAttachments = Boolean(props?.hasAttachments || (props as any)?.attachments?.length || (props as any)?.hasStickers);
    if (!content.trim() && !hasAttachments) return;

    // Never sign a message that already carries a payload (edits, resends, forwarded text).
    if (hasPayload(content)) return;

    const keyId = settings.store.signingKeyId;
    if (!keyId) return fail("No signing key selected.");

    let toastShown = false;
    const toastTimer = setTimeout(() => {
        toastShown = true;
        Toasts.show({
            message: "Signing — touch your YubiKey if it is blinking…",
            id: Toasts.genId(),
            type: Toasts.Type.MESSAGE,
            options: { duration: settings.store.touchTimeoutMs, position: Toasts.Position.BOTTOM }
        });
    }, 2000);

    // Bind the signature to where and when it is being sent, so it cannot be lifted into another
    // channel and still verify. The author id is our own — the receiver checks it against the
    // rendered message, which is why it does not need to travel inside the payload.
    const ctx = {
        platform: "discord" as const,
        conversationId: channelId,
        authorId: UserStore.getCurrentUser()?.id ?? "",
        timestamp: Math.floor(Date.now() / 1000)
    };
    if (!isUsableContext(ctx)) {
        clearTimeout(toastTimer);
        return fail("Could not determine the channel or your own user id.");
    }

    // If the message ends with a URL (e.g. Tenor GIF, Giphy, media link), append a space to the text
    // before signing so Discord's URL regex parser terminates the link and embeds the GIF/video properly.
    const textToSign = (content && /https?:\/\/[^\s]+$/.test(content)) ? content + " " : content;

    let signing: Awaited<ReturnType<typeof Native.sign>>;
    try {
        // Awaiting here does not block the UI thread: gpg runs in the main process.
        signing = await Native.sign(
            canonicalSignedText(ctx, textToSign),
            keyId,
            settings.store.touchTimeoutMs,
            settings.store.gpgPath
        );
    } catch (e) {
        // The IPC call itself failed (native helper missing on a web build, main process threw).
        // Without this the rejection escapes onBeforeSend and the message is sent unsigned,
        // silently defeating failClosed.
        return fail(`Could not reach the signing helper. ${String((e as Error)?.message ?? e)}`.trim());
    } finally {
        clearTimeout(toastTimer);
        if (toastShown) {
            Toasts.pop();
        }
    }

    if (!signing.ok)
        return fail(`${ERROR_MESSAGES[signing.code]} ${signing.error}`.trim());

    try {
        const payload = encodePayload(
            new Uint8Array(signing.sig),
            BASE4,
            keyId.slice(-16),
            ctx.timestamp
        );
        msg.content = attachPayload(textToSign, payload);
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
        return;
    }

    const gpg = await Native.whereIsGpg(settings.store.gpgPath);
    if (!gpg) return;

    if (settings.store.signingKeyId) return;

    const keys = await Native.listSecretKeys(settings.store.gpgPath);
    const chosen = keys.find(k => k.onCard) ?? (keys.length === 1 ? keys[0] : undefined);
    if (!chosen) return;

    settings.store.signingKeyId = chosen.keyId;
    showToast(`InvisiblePGP: signing key ${chosen.uid}${chosen.onCard ? " (smartcard)" : ""}`, Toasts.Type.SUCCESS);
}


import { openIntegrityModal } from "./components/IntegrityModal";

/** Right-click targets that carry a channel: text channels, DMs and group DMs. */
const CHANNEL_MENUS = ["channel-context", "user-context", "gdm-context", "thread-context"];

const signHerePatch: NavContextMenuPatchCallback = (children, props: any) => {
    const channelId = props?.channel?.id ?? props?.channelId;
    if (!channelId) return;

    const on = isChannelSigned(channelId);

    children.push(
        <Menu.MenuItem
            id="vc-ipgp-sign-here"
            label={on ? "Stop signing here" : "Sign messages here"}
            action={async () => {
                const next = await toggleChannelSigned(channelId);
                showToast(
                    next ? "Signing on for this conversation." : "Signing off for this conversation.",
                    next ? Toasts.Type.SUCCESS : Toasts.Type.MESSAGE
                );
            }}
        />
    );
};

const messageMenuPatch: NavContextMenuPatchCallback = (children, props: any) => {
    const message = props?.message;
    if (!message) return;

    children.push(
        <Menu.MenuItem
            id="vc-ipgp-verify-integrity"
            label="Verify PGP Integrity"
            action={() => openIntegrityModal(message)}
        />
    );
};

export default definePlugin({
    name: "InvisiblePGP",
    description:
        "Signs your messages with a detached OpenPGP signature hidden in invisible characters, and "
        + "verifies everyone else's. Signing is delegated to gpg-agent, so hardware keys work.",
    authors: [AUTHOR],
    dependencies: ["MessageEventsAPI", "ContextMenuAPI", "MessageDecorationsAPI", "MessageAccessoriesAPI"],
    settings,

    contextMenus: {
        "channel-context": signHerePatch,
        "thread-context": signHerePatch,
        "gdm-context": signHerePatch,
        "user-context": signHerePatch,
        "message": messageMenuPatch,
        "message-actions": messageMenuPatch
    },

    start() {
        void loadKeyring();
        void loadTrustedSigners();
        void loadChannelPolicy();
        addMessagePreSendListener(onBeforeSend);
        void autoConfigure();
    },

    stop() {
        removeMessagePreSendListener(onBeforeSend);
        clearCache();
    },

    flux: {
        // An edit rewrites the signed text, so the previous verdict is stale.
        MESSAGE_UPDATE({ message }: { message: Message; }) {
            if (message?.id) invalidate(message.id);
        },

        // Strip the trailing invisible signature when editing a message so the cursor lands
        // at the end of the visible text instead of after hundreds of zero-width characters.
        MESSAGE_START_EDIT(action: { channelId: string; messageId: string; content?: string; }) {
            if (action.content) {
                action.content = decodeMessage(action.content).visibleText;
            } else if (action.channelId && action.messageId) {
                const msg = MessageStore.getMessage(action.channelId, action.messageId);
                if (msg?.content) {
                    action.content = decodeMessage(msg.content).visibleText;
                }
            }
        }
    },

    /**
     * Shown under/with the message: signature badge for this message,
     * and an offer card when a public key is shared.
     */
    renderMessageAccessory: (props: { message: Message; }) => (
        <>
            <SignatureBadge message={props.message} />
            <PublicKeyOffer message={props.message} />
        </>
    )
});
