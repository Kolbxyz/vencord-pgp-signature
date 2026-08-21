/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Button, ChannelStore, Forms, useEffect, useState } from "@webpack/common";

import { getSignedChannels, loadChannelPolicy, setChannelSigned } from "../channelPolicy";

/** Review of everywhere signing is switched on — the list that says what you are committing to. */
export function SignedChannelsManager() {
    const [entries, setEntries] = useState<Array<[string, number]>>([]);

    const refresh = () => setEntries(Object.entries(getSignedChannels()));

    useEffect(() => { loadChannelPolicy().then(refresh); }, []);

    async function disable(channelId: string) {
        await setChannelSigned(channelId, false);
        refresh();
    }

    function describe(channelId: string): string {
        const channel = ChannelStore.getChannel(channelId);
        if (!channel) return channelId;
        if (channel.name) return `#${channel.name}`;

        const dm = channel.recipients?.[0];
        return dm ? `DM · ${dm}` : channelId;
    }

    return (
        <Forms.FormSection title="Channels where you sign">
            <Forms.FormText>
                Signing is off everywhere until you turn it on. Right-click a channel or a DM and
                pick "Sign messages here".
            </Forms.FormText>

            {entries.length === 0
                ? <Forms.FormText>Signing is off everywhere.</Forms.FormText>
                : entries.map(([channelId, since]) => (
                    <div key={channelId} style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 6 }}>
                        <Forms.FormText style={{ flex: 1 }}>
                            <b>{describe(channelId)}</b> — since {new Date(since).toLocaleDateString()}
                        </Forms.FormText>
                        <Button size={Button.Sizes.SMALL} color={Button.Colors.RED} onClick={() => disable(channelId)}>
                            Stop signing
                        </Button>
                    </div>
                ))}
        </Forms.FormSection>
    );
}
