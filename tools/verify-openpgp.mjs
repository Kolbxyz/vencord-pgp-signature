/* Replays the plugin's inbound path: decodeZeroWidthToSignature -> openpgp.verify.
   Same call sequence as src/plugins/invisiblePgp/verify.ts. */
import { readFileSync } from "fs";
import * as openpgp from "openpgp";
import { decodeZeroWidthToSignature } from "./.zeroWidth.build.mjs";

const [signedFile, pubKeyFile] = process.argv.slice(2);

const decoded = decodeZeroWidthToSignature(readFileSync(signedFile, "utf8"));
if (!decoded.sigBuffer) {
    console.log("verdict: UNSIGNED");
    process.exit(1);
}

const signature = await openpgp.readSignature({ binarySignature: decoded.sigBuffer });
const packetKeyId = signature.getSigningKeyIDs()[0]?.toHex().toUpperCase();

console.log(`payload      : ${decoded.sigBuffer.length} B`);
console.log(`key id frame : ${decoded.keyId ?? "none"}`);
console.log(`key id packet: ${packetKeyId ?? "none"}`);
console.log(`match        : ${packetKeyId === decoded.keyId ? "yes" : "NO"}`);

const publicKey = await openpgp.readKey({ armoredKey: readFileSync(pubKeyFile, "utf8") });
const uid = (await publicKey.getPrimaryUser()).user.userID?.userID;

try {
    const result = await openpgp.verify({
        message: await openpgp.createMessage({ text: decoded.visibleText }),
        signature,
        verificationKeys: publicKey,
        expectSigned: true,
        format: "utf8"
    });
    await result.signatures[0].verified;
    console.log(`\nverdict: VERIFIED -- ${uid}`);
    console.log(`fingerprint: ${publicKey.getFingerprint().toUpperCase()}`);
} catch (e) {
    console.log(`\nverdict: SIGNATURE BROKEN -- ${e.message}`);
    process.exit(2);
}
