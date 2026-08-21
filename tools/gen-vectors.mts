/*
 * Generates tests/vectors.json — the shared contract between the TypeScript plugin and the Python
 * Synapse module.
 *
 * Both implementations read this file and must agree on every case. It is committed rather than
 * generated at test time on purpose: if a refactor changes the wire format, the diff shows up in
 * review instead of silently regenerating itself into agreement.
 *
 * Regenerate with `npm run vectors`, and read the diff before committing it.
 */

import { writeFileSync } from "node:fs";

import {
    ALPHABETS, buildFrame, encodeBytes, encodePayload, FRAME_V1
} from "../src/plugins/invisiblePgp/codec.ts";
import { canonicalSignedText, MessageContext } from "../src/plugins/invisiblePgp/binding.ts";

const hex = (bytes: Uint8Array) => [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");

/** Deterministic filler so the file is stable across runs. */
const sig = (length: number, seed = 1) =>
    new Uint8Array(length).map((_, i) => (i * 31 + seed * 17 + 7) & 0xFF);

const KEY_ID = "A1B2C3D4E5F60718";
const TS = 1787314443;

interface CodecVector {
    name: string;
    why: string;
    alphabet: string;
    /** The full message a client would see. */
    message: string;
    /** Expected outcome: either a decoded frame, or null meaning "must be rejected". */
    expect: null | { visibleText: string; sigHex: string; keyId: string | null; timestamp: number | null; };
}

const codec: CodecVector[] = [];

for (const alphabet of ALPHABETS) {
    const payload = encodePayload(sig(119), alphabet, KEY_ID, TS);

    codec.push({
        name: `${alphabet.name}/full`,
        why: "A normal signed message: key id and timestamp both present.",
        alphabet: alphabet.name,
        message: "Hello, this message is signed. Emoji: 🔐🗝️" + payload,
        expect: {
            visibleText: "Hello, this message is signed. Emoji: 🔐🗝️",
            sigHex: hex(sig(119)), keyId: KEY_ID, timestamp: TS
        }
    });

    codec.push({
        name: `${alphabet.name}/no-key-id`,
        why: "The key id is optional; v2 omits its eight bytes entirely when absent.",
        alphabet: alphabet.name,
        message: "bare" + encodePayload(sig(64, 2), alphabet, undefined, TS),
        expect: { visibleText: "bare", sigHex: hex(sig(64, 2)), keyId: null, timestamp: TS }
    });

    codec.push({
        name: `${alphabet.name}/no-timestamp`,
        why: "Without a timestamp the signature covers the bare text, not a context binding.",
        alphabet: alphabet.name,
        message: "unbound" + encodePayload(sig(64, 3), alphabet, KEY_ID, undefined),
        expect: { visibleText: "unbound", sigHex: hex(sig(64, 3)), keyId: KEY_ID, timestamp: null }
    });

    codec.push({
        name: `${alphabet.name}/empty-text`,
        why: "A message may be nothing but a payload.",
        alphabet: alphabet.name,
        message: payload,
        expect: { visibleText: "", sigHex: hex(sig(119)), keyId: KEY_ID, timestamp: TS }
    });

    codec.push({
        name: `${alphabet.name}/emoji-before-payload`,
        why: "U+FE0F is both an alphabet symbol and the emoji presentation selector. The anchor is "
            + "what keeps a real emoji at the end of the text out of the payload run.",
        alphabet: alphabet.name,
        message: "ends in an emoji ❤️" + payload,
        expect: {
            visibleText: "ends in an emoji ❤️", sigHex: hex(sig(119)), keyId: KEY_ID, timestamp: TS
        }
    });

    codec.push({
        name: `${alphabet.name}/truncated`,
        why: "A payload missing its tail must be rejected, never read as a shorter signature.",
        alphabet: alphabet.name,
        message: ("hello" + payload).slice(0, -8),
        expect: null
    });

    codec.push({
        name: `${alphabet.name}/padded`,
        why: "Extra symbols the length field does not account for must be rejected.",
        alphabet: alphabet.name,
        message: "hello" + payload + alphabet.symbols[0],
        expect: null
    });
}

codec.push({
    name: "unsigned/plain",
    why: "Ordinary text is returned untouched.",
    alphabet: "none",
    message: "just a normal message",
    expect: null
});

codec.push({
    name: "unsigned/emoji-only",
    why: "The single most important negative case: a global strip would eat the U+FE0F in ❤️.",
    alphabet: "none",
    message: "I ❤️ you 👍🏽 🏳️‍🌈",
    expect: null
});

{
    // A legacy v1 frame: magic | flags | keyId(8, always reserved) | ts(4) | sigLen(2) | sig.
    const s = sig(119, 4);
    const frame = new Uint8Array(16 + s.length);
    frame[0] = FRAME_V1;
    frame[1] = 0b11;
    for (let i = 0; i < 8; i++) frame[2 + i] = parseInt(KEY_ID.slice(i * 2, i * 2 + 2), 16);
    const view = new DataView(frame.buffer);
    view.setUint32(10, TS);
    view.setUint16(14, s.length);
    frame.set(s, 16);

    codec.push({
        name: "base4/legacy-v1",
        why: "Messages signed before the format change must keep verifying, anchor absent and all.",
        alphabet: "base4",
        message: "an old signed message" + encodeBytes(frame, ALPHABETS[0]),
        expect: {
            visibleText: "an old signed message", sigHex: hex(s), keyId: KEY_ID, timestamp: TS
        }
    });
}

{
    const frame = buildFrame(sig(32, 5), KEY_ID, TS);
    frame[1] |= 0b100; // a flag bit with no meaning
    codec.push({
        name: "frame/unknown-flag",
        why: "Unused flag bits are rejected so that each frame has exactly one byte representation.",
        alphabet: "base16",
        message: "hi" + "͏" + encodeBytes(frame, ALPHABETS[1]),
        expect: null
    });
}

interface BindingVector {
    name: string;
    why: string;
    frameVersion: number;
    context: MessageContext;
    visibleText: string;
    canonical: string;
}

const contexts: Array<[string, string, MessageContext, string]> = [
    ["discord/basic", "The everyday Discord case.",
        { platform: "discord", conversationId: "1234567890123456789", authorId: "9876543210987654321", timestamp: TS },
        "Hello, this message is signed."],
    ["matrix/basic", "Matrix ids are not digits, which is why v1 could not express them.",
        { platform: "matrix", conversationId: "!AbCdEf:example.org", authorId: "@me:example.org", timestamp: TS },
        "Check this out: https://example.org"],
    ["matrix/unicode-id", "Lengths are UTF-8 byte counts, so a non-ASCII id must not drift.",
        { platform: "matrix", conversationId: "!café:example.org", authorId: "@ünïcøde:example.org", timestamp: TS },
        "naïve façade 🎈"],
    ["matrix/newline-injection", "An id containing the v1 delimiter must not be able to shift a field.",
        { platform: "matrix", conversationId: "!a:x\n@evil:x", authorId: "@me:example.org", timestamp: TS },
        "text"],
    ["matrix/text-mimics-canonical", "Text that looks like a canonical form is still just text.",
        { platform: "matrix", conversationId: "!r:x", authorId: "@me:x", timestamp: TS },
        "ipgp2\n6:matrix\n4:!r:x\n5:@me:x\n1:1\nspoofed"],
    ["discord/empty-text", "An empty body still binds to a conversation, an author and a moment.",
        { platform: "discord", conversationId: "1", authorId: "2", timestamp: 1 },
        ""]
];

const binding: BindingVector[] = contexts.map(([name, why, context, visibleText]) => ({
    name, why, frameVersion: 2, context, visibleText,
    canonical: canonicalSignedText(context, visibleText)
}));

binding.push({
    name: "discord/legacy-v1",
    why: "The pre-v2 canonical form, kept so old signatures still verify.",
    frameVersion: 1,
    context: { platform: "discord", conversationId: "1234567890123456789", authorId: "9876543210987654321", timestamp: TS },
    visibleText: "an old signed message",
    canonical: canonicalSignedText(
        { platform: "discord", conversationId: "1234567890123456789", authorId: "9876543210987654321", timestamp: TS },
        "an old signed message", FRAME_V1)
});

const out = {
    $comment: "Generated by `npm run vectors`. Both the TypeScript and Python implementations must "
        + "pass every case here — this file is the definition of 'the two agree'. Do not hand-edit.",
    version: 2,
    codec,
    binding
};

const path = new URL("../tests/vectors.json", import.meta.url);
writeFileSync(path, JSON.stringify(out, null, 2) + "\n");
console.log(`wrote ${codec.length} codec vectors and ${binding.length} binding vectors`);
