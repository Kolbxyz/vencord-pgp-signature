/* Encodes and decodes through the plugin's real codec. Called by test-pgp.sh. */
import { readFileSync, writeFileSync } from "fs";
import { encodeSignatureToZeroWidth, decodeZeroWidthToSignature } from "./.zeroWidth.build.mjs";

const [mode, ...args] = process.argv.slice(2);

if (mode === "encode") {
    const [textFile, sigFile, keyId, outFile] = args;
    const text = readFileSync(textFile, "utf8");
    const sig = new Uint8Array(readFileSync(sigFile));
    const payload = encodeSignatureToZeroWidth(sig, keyId.slice(-16));
    writeFileSync(outFile, text + payload, "utf8");
    console.log(`signature ${sig.length} B -> ${payload.length} invisible characters, message ${text.length + payload.length}/2000`);
} else if (mode === "decode") {
    const [signedFile, outText, outSig] = args;
    const out = decodeZeroWidthToSignature(readFileSync(signedFile, "utf8"));
    if (!out.sigBuffer) {
        console.error("no readable payload");
        process.exit(2);
    }
    writeFileSync(outText, out.visibleText, "utf8");
    writeFileSync(outSig, Buffer.from(out.sigBuffer));
    console.log(`payload read: ${out.sigBuffer.length} B, key id ${out.keyId ?? "none"}, visible text ${out.visibleText.length} characters`);
} else {
    console.error("usage: pgp-roundtrip.mjs encode|decode ...");
    process.exit(1);
}
