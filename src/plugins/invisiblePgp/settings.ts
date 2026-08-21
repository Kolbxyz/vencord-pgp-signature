/*
 * Vencord, a Discord client mod
 * Copyright (c) 2024 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { definePluginSettings } from "@api/Settings";
import { OptionType } from "@utils/types";

import { KeyringManager } from "./components/KeyringManager";
import { SignedChannelsManager } from "./components/SignedChannelsManager";
import { TrustedSignersManager } from "./components/TrustedSignersManager";
import { SigningKeyPicker } from "./components/SigningKeyPicker";

export const settings = definePluginSettings({
    signedChannels: {
        type: OptionType.COMPONENT,
        description: "Channels where you sign",
        component: SignedChannelsManager
    },
    offerOnPublicKey: {
        type: OptionType.BOOLEAN,
        description: "When someone shares a public key, offer to import it and to sign in that conversation",
        // An offer, never an action: the buttons are the only thing that imports or enables anything.
        default: true
    },
    signingKey: {
        type: OptionType.COMPONENT,
        description: "Signing key (gpg)",
        component: SigningKeyPicker
    },
    signingKeyId: {
        type: OptionType.STRING,
        description: "Key id passed to `gpg --local-user` (filled in by the picker above)",
        default: "",
        hidden: true
    },
    gpgPath: {
        type: OptionType.STRING,
        description: "Path to the gpg binary — leave empty, it is detected automatically",
        default: ""
    },
    touchTimeoutMs: {
        type: OptionType.NUMBER,
        description: "How long to wait for the YubiKey touch or PIN, in milliseconds",
        default: 30_000
    },
    alphabet: {
        type: OptionType.SELECT,
        description: "Invisible alphabet used for outgoing signatures (all of them are read on receive)",
        options: [
            {
                label: "base16 — VS1-VS16, half the characters of base4 (recommended)",
                value: "base16",
                default: true
            },
            { label: "base256 — VS1-VS256, fewest codepoints, least widely tested", value: "base256" },
            { label: "base4 — zero-width characters, the most conservative choice", value: "base4" }
        ]
    },
    failClosed: {
        type: OptionType.BOOLEAN,
        description: "Cancel sending if signing fails (otherwise the message goes out unsigned)",
        default: true
    },
    clockToleranceSec: {
        type: OptionType.NUMBER,
        description: "Clock drift tolerated between signing and posting, in seconds",
        default: 300
    },
    allowNetworkLookup: {
        type: OptionType.BOOLEAN,
        description: "Look unknown public keys up online (WKD, Keyoxide, keys.openpgp.org)",
        default: true
    },
    keyTtlDays: {
        type: OptionType.NUMBER,
        description: "How long keys fetched online stay cached, in days",
        default: 7
    },
    showUnsignedBadge: {
        type: OptionType.BOOLEAN,
        description: "Show a discreet \"Unsigned\" marker on messages without a signature",
        default: false
    },
    autoPinSigners: {
        type: OptionType.BOOLEAN,
        description: "Remember the key of anyone who signs validly, then flag their unsigned messages",
        default: true
    },
    trustedSigners: {
        type: OptionType.COMPONENT,
        description: "Expected signers",
        component: TrustedSignersManager
    },
    keyring: {
        type: OptionType.COMPONENT,
        description: "Public keyring",
        component: KeyringManager
    }
});
