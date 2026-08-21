/* Measures which alphabets survive a real platform.
 *
 * SPEC.md picks the default alphabet from measurement rather than theory, and this is what produces
 * the numbers. Send each probe through the platform under test, then paste what comes back.
 *
 *   node roundtrip-probe.mjs emit          # prints one probe message per alphabet
 *   node roundtrip-probe.mjs check <file>  # reads them back and reports what survived
 */
import { readFileSync } from "fs";

import { alphabetByName, ALPHABETS, decodeMessage, encodePayload } from "./.build/codec.mjs";

const KEY_ID = "A1B2C3D4E5F60718";
const TIMESTAMP = 1787314443;
/** Deterministic stand-in for a 119-byte Ed25519 signature, so a mismatch is easy to spot. */
const SIGNATURE = new Uint8Array(119).map((_, i) => (i * 31 + 7) & 0xFF);

const label = name => `probe:${name}`;

const [mode, file] = process.argv.slice(2);

if (mode === "emit") {
    console.log("Send each line below through the platform, then paste the replies into a file");
    console.log("and run: node roundtrip-probe.mjs check <file>\n");

    for (const alphabet of ALPHABETS) {
        const payload = encodePayload(SIGNATURE, alphabet, KEY_ID, TIMESTAMP);
        const message = label(alphabet.name) + payload;
        console.log(message);
        console.error(`  ${alphabet.name}: ${[...payload].length} codepoints, `
            + `${payload.length} UTF-16 units, ${message.length} total`);
    }
} else if (mode === "check") {
    if (!file) {
        console.error("usage: node roundtrip-probe.mjs check <file>");
        process.exit(1);
    }

    const lines = readFileSync(file, "utf8").split("\n").filter(l => l.trim());
    const seen = new Map();

    for (const line of lines) {
        const decoded = decodeMessage(line);
        const name = decoded.visibleText.replace("probe:", "").trim();
        if (!name) continue;

        if (!decoded.frame) {
            seen.set(name, "LOST — no readable payload came back");
            continue;
        }

        const intact = decoded.frame.sig.length === SIGNATURE.length
            && decoded.frame.sig.every((b, i) => b === SIGNATURE[i])
            && decoded.frame.keyId === KEY_ID
            && decoded.frame.timestamp === TIMESTAMP;

        seen.set(name, intact ? "SURVIVED" : "CORRUPTED — payload came back altered");
    }

    let failures = 0;
    for (const alphabet of ALPHABETS) {
        const result = seen.get(alphabet.name) ?? "NOT TESTED — no probe line found";
        if (!result.startsWith("SURVIVED")) failures++;
        console.log(`${alphabet.name.padEnd(8)} ${result}`);
    }

    console.log("\nRecord these in the table in SPEC.md §7.");
    process.exit(failures === ALPHABETS.length ? 1 : 0);
} else {
    console.error("usage: roundtrip-probe.mjs emit | check <file>");
    process.exit(1);
}
