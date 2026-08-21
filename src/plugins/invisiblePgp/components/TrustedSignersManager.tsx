/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Button, Forms, useEffect, useState } from "@webpack/common";

import { getTrustedSigners, loadTrustedSigners, TrustedSigner, unpinSigner } from "../trustedSigners";
import { clearCache } from "../verify";

/**
 * The list of accounts whose messages must be signed. Removing someone is the only destructive
 * action here, and it is reversible — the next valid signature re-pins them.
 */
export function TrustedSignersManager() {
    const [entries, setEntries] = useState<Array<[string, TrustedSigner]>>([]);

    const refresh = () => setEntries(Object.entries(getTrustedSigners()));

    useEffect(() => { loadTrustedSigners().then(refresh); }, []);

    async function remove(userId: string) {
        await unpinSigner(userId);
        clearCache();
        refresh();
    }

    return (
        <Forms.FormSection title="Expected signers">
            <Forms.FormText>
                Unsigned messages from these accounts are flagged in red. Each one is added
                automatically the first time it produces a valid signature.
            </Forms.FormText>

            {entries.length === 0
                ? <Forms.FormText>Nobody yet.</Forms.FormText>
                : entries.map(([userId, s]) => (
                    <div key={userId} style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 6 }}>
                        <Forms.FormText style={{ flex: 1 }}>
                            <b>{s.username || userId}</b> — <code>{s.fingerprint.slice(-16)}</code>
                            {s.uid ? ` (${s.uid})` : ""}
                            {s.source === "manual" ? " · pinned by hand" : " · detected"}
                        </Forms.FormText>
                        <Button size={Button.Sizes.SMALL} color={Button.Colors.RED} onClick={() => remove(userId)}>
                            Remove
                        </Button>
                    </div>
                ))}
        </Forms.FormSection>
    );
}
