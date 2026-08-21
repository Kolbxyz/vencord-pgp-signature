/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Forms, Select, useEffect, useState } from "@webpack/common";

import { Native } from "../native.bridge";
import { settings } from "../settings";
import { GpgKeyInfo } from "../types";

/** Lists the local secret keys so the user picks one instead of typing a fingerprint by hand. */
export function SigningKeyPicker() {
    const [keys, setKeys] = useState<GpgKeyInfo[] | null>(null);
    const [binary, setBinary] = useState<string | null | undefined>(undefined);
    const { signingKeyId, gpgPath } = settings.use(["signingKeyId", "gpgPath"]);

    useEffect(() => {
        let cancelled = false;
        (async () => {
            const found = await Native.whereIsGpg(gpgPath);
            if (cancelled) return;
            setBinary(found);
            setKeys(found ? await Native.listSecretKeys(gpgPath) : []);
        })();
        return () => { cancelled = true; };
    }, [gpgPath]);

    if (binary === null) {
        return (
            <Forms.FormSection title="Signing key">
                <Forms.FormText style={{ color: "var(--text-danger)" }}>
                    gpg was not found. Install GnuPG (and gpg-agent), then set its path below.
                    Signing only works in Vencord Desktop.
                </Forms.FormText>
            </Forms.FormSection>
        );
    }

    const options = (keys ?? []).map(k => ({
        label: `${k.uid} — ${k.algo}${k.onCard ? " (smartcard / YubiKey)" : ""}`,
        value: k.keyId
    }));

    return (
        <Forms.FormSection title="Signing key">
            <Select
                options={options}
                placeholder={keys === null ? "Reading the keyring…" : "Pick a secret key"}
                isSelected={v => v === signingKeyId}
                select={v => { settings.store.signingKeyId = v; }}
                serialize={v => String(v)}
                closeOnSelect
            />
            {keys?.length === 0 && (
                <Forms.FormText>No secret key found in your gpg keyring.</Forms.FormText>
            )}
            {signingKeyId && <Forms.FormText>Key ID : <code>{signingKeyId}</code></Forms.FormText>}
            {binary && <Forms.FormText>gpg found at <code>{binary}</code></Forms.FormText>}
        </Forms.FormSection>
    );
}
