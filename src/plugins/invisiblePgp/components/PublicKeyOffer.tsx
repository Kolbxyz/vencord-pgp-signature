/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import ErrorBoundary from "@components/ErrorBoundary";
import { Button, Forms, useState } from "@webpack/common";

import { isChannelSigned, setChannelSigned } from "../channelPolicy";
import { storeKey } from "../keyResolver";
import { fetchArmoredKey, findKeyAttachment, findPublicKeyBlock } from "../publicKeyDetection";
import { settings } from "../settings";
import { pinSigner } from "../trustedSigners";
import { clearCache, parseArmoredKey } from "../verify";

/**
 * Shown under a message that carries someone's public key.
 *
 * Nothing here happens on its own: the key is not downloaded, not imported, and signing is not
 * switched on until the button is pressed. Detection is synchronous and local — an attachment is
 * recognised by its name, and only fetched once you ask for it.
 */
function PublicKeyOfferInner({ message }: { message: any; }) {
    const { offerOnPublicKey } = settings.use(["offerOnPublicKey"]);
    const [imported, setImported] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);
    const [signing, setSigning] = useState(() => isChannelSigned(message?.channel_id));

    if (!offerOnPublicKey || !message) return null;

    const inline = findPublicKeyBlock(message.content);
    const attachment = findKeyAttachment(message.attachments);
    if (!inline && !attachment) return null;

    async function addToKeyring() {
        setBusy(true);
        setError(null);
        try {
            const armored = inline ?? await fetchArmoredKey(attachment!.url!);
            if (!armored) throw new Error("No readable public key in that file.");

            const { fingerprint, uid } = await parseArmoredKey(armored);
            await storeKey({ armored, fingerprint, uid, fetchedAt: Date.now(), manual: true });

            if (message.author?.id) {
                await pinSigner(message.author.id, {
                    fingerprint,
                    keyId: fingerprint.slice(-16),
                    uid: uid || "",
                    username: message.author.username || "",
                    addedAt: Date.now(),
                    lastSeenAt: Date.now(),
                    source: "manual"
                });
            }

            clearCache(); // re-verify messages already on screen against the new key
            setImported(uid || fingerprint);
        } catch (e) {
            setError((e as Error).message);
        } finally {
            setBusy(false);
        }
    }

    async function toggleSigning() {
        const next = !signing;
        await setChannelSigned(message.channel_id, next);
        setSigning(next);
    }

    return (
        <div className="vc-ipgp-offer">
            <Forms.FormText className="vc-ipgp-offer-title">
                {imported
                    ? `Added to your keyring: ${imported}`
                    : `${message.author?.username ?? "Someone"} shared a public key${attachment ? ` (${attachment.filename})` : ""}.`}
            </Forms.FormText>

            <div className="vc-ipgp-offer-actions">
                {!imported && (
                    <Button size={Button.Sizes.SMALL} disabled={busy} onClick={addToKeyring}>
                        {busy ? "Adding…" : "Add to keyring"}
                    </Button>
                )}
                <Button
                    size={Button.Sizes.SMALL}
                    color={signing ? Button.Colors.PRIMARY : Button.Colors.BRAND}
                    onClick={toggleSigning}
                >
                    {signing ? "Stop signing here" : "Sign messages here"}
                </Button>
            </div>

            {error && <Forms.FormText style={{ color: "var(--text-danger)" }}>{error}</Forms.FormText>}
        </div>
    );
}

export const PublicKeyOffer = ErrorBoundary.wrap(PublicKeyOfferInner, { noop: true });
