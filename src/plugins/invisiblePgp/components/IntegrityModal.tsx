import ErrorBoundary from "@components/ErrorBoundary";
import { Forms, Modal, openModal, Text } from "@webpack/common";
import type { Message } from "discord-types/general";
import { getChannelSignedSince, isChannelSigned } from "../channelPolicy";
import { decodeMessage } from "../codec";
import { settings } from "../settings";
import { getTrustedSigner } from "../trustedSigners";
import { VerifyState, VerifyStatus } from "../types";
import { ensureVerified } from "../verify";

function formatFingerprint(fpr?: string): string {
    if (!fpr) return "N/A";
    return fpr.replace(/(.{4})/g, "$1 ").trim();
}

export function openIntegrityModal(message: Message) {
    const { allowNetworkLookup, keyTtlDays, clockToleranceSec, autoPinSigners } = settings.store;

    const state = ensureVerified(
        {
            messageId: message.id,
            content: message.content ?? "",
            channelId: message.channel_id,
            authorId: message.author?.id ?? "",
            postedAt: Math.floor(new Date(message.timestamp as unknown as string).getTime() / 1000),
            hintUid: getTrustedSigner(message.author?.id ?? "")?.uid,
            username: message.author?.username,
            clockToleranceSec,
            autoPin: autoPinSigners
        },
        { allowNetwork: allowNetworkLookup, ttlDays: keyTtlDays }
    );

    const decoded = decodeMessage(message.content ?? "");
    const isSignedRoom = isChannelSigned(message.channel_id);
    const enabledSinceMs = getChannelSignedSince(message.channel_id);
    const msgTimeMs = new Date(message.timestamp as unknown as string).getTime();
    const sentBeforeEnabling = Boolean(enabledSinceMs && msgTimeMs < enabledSinceMs);

    let effectiveStatus = state.status;
    let effectiveReason = state.reason;

    if (!decoded.frame) {
        if (!isSignedRoom) {
            effectiveStatus = VerifyStatus.Unsigned;
            effectiveReason = "Signing is not enabled for this conversation.";
        } else if (sentBeforeEnabling) {
            effectiveStatus = VerifyStatus.Unsigned;
            effectiveReason = "Message was posted before PGP signature was enabled in this channel.";
        }
    }

    openModal(modalProps => (
        <ErrorBoundary>
            <Modal
                {...modalProps}
                title="OpenPGP Signature Verification"
            subtitle={`Message ID: ${message.id}`}
            size="md"
            actions={[
                {
                    text: "Close",
                    variant: "primary",
                    onClick: modalProps.onClose
                }
            ]}
        >
            <div style={{ display: "flex", flexDirection: "column", gap: "14px", padding: "8px 0" }}>
                {/* Status Box */}
                <div style={{
                    padding: "12px",
                    borderRadius: "6px",
                    background: effectiveStatus === VerifyStatus.Valid
                        ? "color-mix(in srgb, var(--text-positive, #3ba55d) 15%, transparent)"
                        : effectiveStatus === VerifyStatus.Unsigned
                            ? "var(--background-secondary, #2b2d31)"
                            : "color-mix(in srgb, var(--text-danger, #ed4245) 15%, transparent)",
                    border: `1px solid ${effectiveStatus === VerifyStatus.Valid
                        ? "var(--text-positive, #3ba55d)"
                        : effectiveStatus === VerifyStatus.Unsigned
                            ? "var(--background-modifier-accent, #4f545c)"
                            : "var(--text-danger, #ed4245)"}`
                }}>
                    <Text variant="text-md/bold" style={{
                        color: effectiveStatus === VerifyStatus.Valid
                            ? "var(--text-positive, #3ba55d)"
                            : effectiveStatus === VerifyStatus.Unsigned
                                ? "var(--text-muted, #949ba4)"
                                : "var(--text-danger, #ed4245)"
                    }}>
                        {effectiveStatus === VerifyStatus.Valid && "✓ Valid OpenPGP Signature"}
                        {effectiveStatus === VerifyStatus.Invalid && "⚠ Signature Broken / Modified"}
                        {effectiveStatus === VerifyStatus.Replayed && "⚠ Replay / Out of Context"}
                        {effectiveStatus === VerifyStatus.MissingSignature && "⚠ Missing Signature (Expected in this signed channel)"}
                        {effectiveStatus === VerifyStatus.KeyChanged && "⚠ Key Changed (Different from pinned key)"}
                        {effectiveStatus === VerifyStatus.UnknownKey && "? Unknown Key (Public key not found)"}
                        {effectiveStatus === VerifyStatus.Error && "! Verification Error"}
                        {effectiveStatus === VerifyStatus.Unsigned && (sentBeforeEnabling ? "○ Unsigned (Sent before enabling PGP)" : "○ Unsigned Message")}
                    </Text>
                    {effectiveReason && (
                        <Text variant="text-sm/normal" style={{ marginTop: "4px", color: "var(--text-muted)" }}>
                            {effectiveReason}
                        </Text>
                    )}
                </div>

                {/* Signer Info */}
                {state.uid && (
                    <div>
                        <Forms.FormTitle tag="h5">Signer Identity</Forms.FormTitle>
                        <Text variant="text-md/medium" style={{ color: "var(--text-normal)" }}>
                            {state.uid}
                        </Text>
                    </div>
                )}

                {/* Fingerprint */}
                {state.fingerprint && (
                    <div>
                        <Forms.FormTitle tag="h5">Public Key Fingerprint</Forms.FormTitle>
                        <Text variant="code" style={{ wordBreak: "break-all" }}>
                            {formatFingerprint(state.fingerprint)}
                        </Text>
                    </div>
                )}

                {/* Key ID & Timestamp */}
                {(state.keyId || decoded.frame?.keyId) && (
                    <div style={{ display: "flex", gap: "24px" }}>
                        <div>
                            <Forms.FormTitle tag="h5">Key ID</Forms.FormTitle>
                            <Text variant="code">{state.keyId || decoded.frame?.keyId}</Text>
                        </div>
                        {decoded.frame?.signedAt && (
                            <div>
                                <Forms.FormTitle tag="h5">Signature Time</Forms.FormTitle>
                                <Text variant="text-sm/normal">
                                    {new Date(decoded.frame.signedAt * 1000).toLocaleString()}
                                </Text>
                            </div>
                        )}
                    </div>
                )}

                {/* Encoding & Payload Details */}
                {decoded.frame && (
                    <div>
                        <Forms.FormTitle tag="h5">Encoding & Envelope</Forms.FormTitle>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: "16px", fontSize: "0.85rem", color: "var(--text-muted)" }}>
                            <div>Alphabet: <strong style={{ color: "var(--text-normal)" }}>{decoded.alphabet?.name ?? "unknown"}</strong> ({decoded.alphabet?.bitsPerSymbol ?? "?"} bits/symbol)</div>
                            <div>Envelope: <strong style={{ color: "var(--text-normal)" }}>v{decoded.frame.version}</strong> {decoded.frame.timestamp ? "(context-bound)" : ""}</div>
                            <div>Payload: <strong style={{ color: "var(--text-normal)" }}>{((message.content?.length ?? 0) - decoded.visibleText.length)}</strong> invisible chars</div>
                        </div>
                    </div>
                )}

                {/* Signed Content */}
                <div>
                    <Forms.FormTitle tag="h5">Signed Message Text</Forms.FormTitle>
                    <div style={{
                        padding: "8px 12px",
                        background: "var(--background-secondary, #2b2d31)",
                        borderRadius: "4px",
                        maxHeight: "120px",
                        overflowY: "auto",
                        fontFamily: "monospace",
                        fontSize: "0.85rem",
                        whiteSpace: "pre-wrap",
                        wordBreak: "break-word"
                    }}>
                        {decoded.visibleText || "(empty content)"}
                    </div>
                </div>
            </div>
        </Modal>
    </ErrorBoundary>
    ));
}
