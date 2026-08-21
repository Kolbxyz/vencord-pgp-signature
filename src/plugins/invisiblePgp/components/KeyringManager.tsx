/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Button, Forms, TextArea, useEffect, useState } from "@webpack/common";

import { getKeyring, loadKeyring, removeKey, storeKey } from "../keyResolver";
import { StoredKey } from "../types";
import { clearCache, parseArmoredKey } from "../verify";

/** Manual public key import — the trust anchor for people whose keys aren't published anywhere. */
export function KeyringManager() {
    const [armored, setArmored] = useState("");
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState<string | null>(null);
    const [keys, setKeys] = useState<StoredKey[]>([]);

    const refresh = () => setKeys(Object.values(getKeyring()));

    useEffect(() => { loadKeyring().then(refresh); }, []);

    async function importArmoredText(text: string) {
        setError(null);
        setSuccess(null);
        try {
            const { fingerprint, uid } = await parseArmoredKey(text);
            await storeKey({ armored: text.trim(), fingerprint, uid, fetchedAt: Date.now(), manual: true });
            clearCache(); // re-verify already-rendered messages against the new key
            setArmored("");
            setSuccess(`Imported: ${uid || fingerprint} (${fingerprint.slice(-16)})`);
            refresh();
        } catch (e) {
            setError(`Unreadable key: ${(e as Error).message}`);
        }
    }

    async function onImport() {
        await importArmoredText(armored);
    }

    function onFileSelect(e: React.ChangeEvent<HTMLInputElement>) {
        const file = e.target.files?.[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = async () => {
            const text = String(reader.result ?? "");
            setArmored(text);
            await importArmoredText(text);
        };
        reader.readAsText(file);
    }

    async function onRemove(key: StoredKey) {
        await removeKey(key.fingerprint.slice(-16));
        clearCache();
        refresh();
    }

    return (
        <Forms.FormSection title="Public keyring">
            <TextArea
                value={armored}
                onChange={setArmored}
                placeholder={"-----BEGIN PGP PUBLIC KEY BLOCK-----\n…"}
                rows={5}
            />
            <div style={{ display: "flex", gap: "8px", marginTop: "8px", alignItems: "center" }}>
                <Button size={Button.Sizes.SMALL} disabled={!armored.trim()} onClick={onImport}>
                    Import from text
                </Button>
                <label className="vc-ipgp-file-btn" style={{
                    display: "inline-flex",
                    alignItems: "center",
                    justifyContent: "center",
                    padding: "0 16px",
                    height: "32px",
                    borderRadius: "3px",
                    fontSize: "14px",
                    fontWeight: 500,
                    cursor: "pointer",
                    background: "var(--brand-experiment, #5865f2)",
                    color: "#fff"
                }}>
                    Upload .asc / .key file
                    <input
                        type="file"
                        accept=".asc,.gpg,.pgp,.key,.pub,.txt"
                        style={{ display: "none" }}
                        onChange={onFileSelect}
                    />
                </label>
            </div>
            {error && <Forms.FormText style={{ color: "var(--text-danger)", marginTop: "4px" }}>{error}</Forms.FormText>}
            {success && <Forms.FormText style={{ color: "var(--text-positive)", marginTop: "4px" }}>{success}</Forms.FormText>}

            {keys.length === 0
                ? <Forms.FormText>No keys stored. Keys found online are added here automatically.</Forms.FormText>
                : keys.map(k => (
                    <div key={k.fingerprint} style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 6 }}>
                        <Forms.FormText style={{ flex: 1 }}>
                            {k.uid || k.fingerprint} — <code>{k.fingerprint.slice(-16)}</code>
                            {k.manual ? " (imported)" : " (from the network)"}
                        </Forms.FormText>
                        <Button size={Button.Sizes.SMALL} color={Button.Colors.RED} onClick={() => onRemove(k)}>
                            Remove
                        </Button>
                    </div>
                ))}
        </Forms.FormSection>
    );
}
