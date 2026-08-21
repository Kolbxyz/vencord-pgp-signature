/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import ErrorBoundary from "@components/ErrorBoundary";
import { Tooltip, useEffect, useState } from "@webpack/common";
import type { Message } from "discord-types/general";

import { getChannelSignedSince, isChannelSigned } from "../channelPolicy";
import { settings } from "../settings";
import { getTrustedSigner } from "../trustedSigners";
import { VerifyState, VerifyStatus } from "../types";
import { ensureVerified, getCached, subscribe } from "../verify";

interface Appearance {
    icon: string;
    label: string;
    tooltip: (s: VerifyState) => string;
    className: string;
}

const APPEARANCE: Record<VerifyStatus, Appearance> = {
    [VerifyStatus.Pending]: {
        icon: "⋯",
        label: "Checking",
        className: "vc-ipgp-badge vc-ipgp-pending",
        tooltip: () => "Checking the OpenPGP signature…"
    },
    [VerifyStatus.Valid]: {
        icon: "✓",
        label: "Verified",
        className: "vc-ipgp-badge vc-ipgp-valid",
        tooltip: s => `Valid OpenPGP signature\n${s.uid ?? "unknown key"}\n${formatFingerprint(s.fingerprint)}`
    },
    [VerifyStatus.Invalid]: {
        icon: "⚠",
        label: "Signature broken",
        className: "vc-ipgp-badge vc-ipgp-invalid",
        tooltip: s => `This message does not match its signature.\n${s.reason ?? ""}`.trim()
    },
    [VerifyStatus.Replayed]: {
        icon: "⚠",
        label: "Out of context",
        className: "vc-ipgp-badge vc-ipgp-invalid",
        tooltip: s => `Signed for a different moment than when this message was posted.\n${s.reason ?? ""}`.trim()
    },
    [VerifyStatus.MissingSignature]: {
        icon: "⚠",
        label: "Unsigned — signature expected",
        className: "vc-ipgp-badge vc-ipgp-invalid",
        tooltip: s => `${s.reason ?? ""}\nThis one carries none, so it may not be from them.`.trim()
    },
    [VerifyStatus.KeyChanged]: {
        icon: "⚠",
        label: "Different key",
        className: "vc-ipgp-badge vc-ipgp-invalid",
        tooltip: s => "Valid signature, but not made with the key pinned for this account.\n"
            + `pinned: ${formatFingerprint(s.pinnedFingerprint)}\nused: ${formatFingerprint(s.fingerprint)}`
    },
    [VerifyStatus.UnknownKey]: {
        icon: "?",
        label: "Key not found",
        className: "vc-ipgp-badge vc-ipgp-unknown",
        tooltip: s => `Signed, but no public key could be found for ${s.keyId ?? "?"}.\n`
            + "Import it in the plugin settings, or turn on online lookup."
    },
    [VerifyStatus.Error]: {
        icon: "!",
        label: "Error",
        className: "vc-ipgp-badge vc-ipgp-invalid",
        tooltip: s => s.reason ?? "Verification failed."
    },
    [VerifyStatus.Unsigned]: {
        icon: "○",
        label: "Unsigned",
        className: "vc-ipgp-badge vc-ipgp-unsigned",
        tooltip: () => "This message carries no OpenPGP signature."
    }
};

function formatFingerprint(fpr?: string): string {
    if (!fpr) return "";
    return fpr.replace(/(.{4})/g, "$1 ").trim();
}

function SignatureBadgeInner({ message }: { message: Message; }) {
    const { allowNetworkLookup, keyTtlDays, showUnsignedBadge, clockToleranceSec, autoPinSigners } =
        settings.use(["allowNetworkLookup", "keyTtlDays", "showUnsignedBadge", "clockToleranceSec", "autoPinSigners"]);

    const [state, setState] = useState<VerifyState>(
        () => getCached(message.id) ?? { status: VerifyStatus.Pending }
    );

    useEffect(() => {
        // Kick the check off outside of render, then follow it through the store.
        const unsubscribe = subscribe((id, next) => {
            if (id === message.id) setState(next);
        });

        setState(ensureVerified(
            {
                messageId: message.id,
                content: message.content ?? "",
                // Read off the rendered message: a copy posted elsewhere no longer matches.
                channelId: message.channel_id,
                authorId: message.author?.id ?? "",
                postedAt: Math.floor(new Date(message.timestamp as unknown as string).getTime() / 1000),
                // WKD/Keyoxide lookup keys off an *email*, which a Discord username never is.
                // The pinned signer's OpenPGP uid does carry one, so that is the only hint worth
                // passing; on first contact it is absent and only the by-key-id servers are tried.
                hintUid: getTrustedSigner(message.author?.id ?? "")?.uid,
                username: message.author?.username,
                clockToleranceSec,
                autoPin: autoPinSigners
            },
            { allowNetwork: allowNetworkLookup, ttlDays: keyTtlDays }
        ));

        return unsubscribe;
        // editedTimestamp: an edit changes the signed text, so the verdict must be recomputed.
    }, [message.id, message.content, message.editedTimestamp, allowNetworkLookup, keyTtlDays, clockToleranceSec, autoPinSigners]);

    // Keep chat completely clean: only show visible badge when there is an anomaly/issue!
    if (state.status === VerifyStatus.Valid || state.status === VerifyStatus.Unsigned || state.status === VerifyStatus.Pending) {
        return null;
    }

    // Do not show "MissingSignature" if this channel is not signed or if message was sent before signing was enabled
    if (state.status === VerifyStatus.MissingSignature) {
        if (!isChannelSigned(message.channel_id)) return null;
        const enabledSinceMs = getChannelSignedSince(message.channel_id);
        const msgTimeMs = new Date(message.timestamp as unknown as string).getTime();
        if (enabledSinceMs && msgTimeMs < enabledSinceMs) return null;
    }

    const look = APPEARANCE[state.status];

    return (
        <Tooltip text={look.tooltip(state)}>
            {tooltipProps => (
                <span {...tooltipProps} className={look.className} aria-label={look.label}>
                    {look.icon}
                </span>
            )}
        </Tooltip>
    );
}

export const SignatureBadge = ErrorBoundary.wrap(SignatureBadgeInner, { noop: true });
