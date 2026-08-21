/* Encodes and decodes through the plugin's real codec, over the real canonical signed string.
   Called by test-pgp.sh. */
import { readFileSync, writeFileSync } from "fs";

import { canonicalSignedText } from "./.build/binding.mjs";
import { alphabetByName, decodeMessage, encodePayload } from "./.build/codec.mjs";

const [mode, ...args] = process.argv.slice(2);

/** The context a Discord send would build. Fixed values so the script is reproducible. */
const CONTEXT = {
    platform: "discord",
    conversationId: "1234567890123456789",
    authorId: "9876543210987654321",
    timestamp: Number(process.env.IPGP_TIMESTAMP ?? 1787314443)
};

if (mode === "canonical") {
    // Emits exactly what gpg must sign — this is the step the old script skipped, which is why the
    // context-bound path had no coverage against real gpg at all.
    const [textFile, outFile] = args;
    writeFileSync(outFile, canonicalSignedText(CONTEXT, readFileSync(textFile, "utf8")), "utf8");
    console.log(`   canonical string: ${CONTEXT.platform}/${CONTEXT.conversationId} @ ${CONTEXT.timestamp}`);
} else if (mode === "encode") {
    const [textFile, sigFile, keyId, alphabetName, outFile] = args;
    const text = readFileSync(textFile, "utf8");
    const sig = new Uint8Array(readFileSync(sigFile));
    const payload = encodePayload(sig, alphabetByName(alphabetName), keyId.slice(-16), CONTEXT.timestamp);

    writeFileSync(outFile, text + payload, "utf8");
    console.log(`   signature ${sig.length} B -> ${[...payload].length} codepoints `
        + `(${payload.length} UTF-16 units) via ${alphabetName}, message ${text.length + payload.length}/2000`);
} else if (mode === "decode") {
    const [signedFile, outText, outSig] = args;
    const decoded = decodeMessage(readFileSync(signedFile, "utf8"));
    if (!decoded.frame) {
        console.error("   !! no readable payload");
        process.exit(2);
    }

    writeFileSync(outText, decoded.visibleText, "utf8");
    writeFileSync(outSig, Buffer.from(decoded.frame.sig));
    console.log(`   payload ${decoded.frame.sig.length} B, alphabet ${decoded.alphabet.name}, `
        + `key id ${decoded.frame.keyId ?? "none"}, timestamp ${decoded.frame.timestamp ?? "none"}`);

    if (decoded.frame.timestamp !== CONTEXT.timestamp) {
        console.error(`   !! timestamp did not survive: ${decoded.frame.timestamp} != ${CONTEXT.timestamp}`);
        process.exit(3);
    }
} else {
    console.error("usage: pgp-roundtrip.mjs canonical|encode|decode ...");
    process.exit(1);
}
