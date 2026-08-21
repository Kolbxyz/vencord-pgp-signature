/* Replays the plugin's inbound path: decodeMessage -> rebuild the canonical string -> openpgp.verify.
   Same call sequence as src/plugins/invisiblePgp/verify.ts.

   usage: node verify-openpgp.mjs <signed-message-file> <public-key-file> [channelId] [authorId] */
import { readFileSync } from "fs";

import * as openpgp from "openpgp";

import { canonicalSignedText } from "./.build/binding.mjs";
import { decodeMessage } from "./.build/codec.mjs";

const [signedFile, pubKeyFile, channelId = "1234567890123456789", authorId = "9876543210987654321"] =
    process.argv.slice(2);

const decoded = decodeMessage(readFileSync(signedFile, "utf8"));
if (!decoded.frame) {
    console.log("verdict: UNSIGNED");
    process.exit(1);
}

const { sig, keyId, timestamp } = decoded.frame;

const signature = await openpgp.readSignature({ binarySignature: sig });
const packetKeyId = signature.getSigningKeyIDs()[0]?.toHex().toUpperCase();

console.log(`alphabet     : ${decoded.alphabet.name}`);
console.log(`payload      : ${sig.length} B`);
console.log(`key id frame : ${keyId ?? "none"}`);
console.log(`key id packet: ${packetKeyId ?? "none"}`);
console.log(`timestamp    : ${timestamp ?? "none (unbound signature)"}`);

// The plugin treats this mismatch as Invalid: the frame hint drives key lookup, so a disagreement
// is an attempt to steer the verifier at a key other than the one that signed.
if (packetKeyId && keyId && packetKeyId !== keyId) {
    console.log("\nverdict: INVALID — the frame's key id contradicts the signature packet");
    process.exit(2);
}

const publicKey = await openpgp.readKey({ armoredKey: readFileSync(pubKeyFile, "utf8") });
const uid = (await publicKey.getPrimaryUser()).user.userID?.userID;

// Without a timestamp the payload predates context binding and covers only the bare text.
const signedText = timestamp === undefined
    ? decoded.visibleText
    : canonicalSignedText(
        { platform: "discord", conversationId: channelId, authorId, timestamp },
        decoded.visibleText
    );

try {
    const result = await openpgp.verify({
        message: await openpgp.createMessage({ text: signedText }),
        signature,
        verificationKeys: publicKey,
        expectSigned: true,
        format: "utf8"
    });
    await result.signatures[0].verified;

    console.log(`\nverdict: VERIFIED -- ${uid}`);
    console.log(`fingerprint: ${publicKey.getFingerprint().toUpperCase()}`);
    if (timestamp !== undefined) console.log(`bound to  : channel ${channelId}, author ${authorId}`);
} catch (e) {
    console.log(`\nverdict: SIGNATURE BROKEN -- ${e.message}`);
    if (timestamp !== undefined)
        console.log("(a wrong channel or author id looks exactly like a broken signature)");
    process.exit(2);
}
