import assert from "assert";
import { encodeSignatureToZeroWidth, decodeZeroWidthToSignature, attachPayload,
         hasZeroWidthPayload, stripZeroWidth, PayloadTooLongError } from "./zeroWidth.mjs";

let n = 0;
const t = (name, fn) => { fn(); n++; console.log("ok -", name); };

t("round-trip ed25519-sized signature", () => {
    const sig = new Uint8Array(100).map((_, i) => (i * 37 + 11) & 0xff);
    const text = "Hello, this message is signed. Accents: éàü — emoji: 🔐🗝️";
    const msg = attachPayload(text, encodeSignatureToZeroWidth(sig, "A1B2C3D4E5F60718"));
    const out = decodeZeroWidthToSignature(msg);
    assert.strictEqual(out.visibleText, text);
    assert.deepStrictEqual(out.sigBuffer, sig);
    assert.strictEqual(out.keyId, "A1B2C3D4E5F60718");
});

t("round-trip without key id", () => {
    const sig = new Uint8Array([0, 255, 1, 128, 64]);
    const out = decodeZeroWidthToSignature("hi" + encodeSignatureToZeroWidth(sig));
    assert.deepStrictEqual(out.sigBuffer, sig);
    assert.strictEqual(out.keyId, undefined);
});

t("all 256 byte values survive", () => {
    const sig = new Uint8Array(256).map((_, i) => i);
    assert.deepStrictEqual(decodeZeroWidthToSignature(encodeSignatureToZeroWidth(sig)).sigBuffer, sig);
});

t("plain message is unsigned", () => {
    const out = decodeZeroWidthToSignature("just a normal message");
    assert.strictEqual(out.sigBuffer, null);
    assert.strictEqual(out.visibleText, "just a normal message");
});

t("truncated payload is rejected, visible text still recovered", () => {
    const sig = new Uint8Array(64).fill(7);
    const msg = "hello" + encodeSignatureToZeroWidth(sig, "0011223344556677");
    const out = decodeZeroWidthToSignature(msg.slice(0, msg.length - 40));
    assert.strictEqual(out.sigBuffer, null);
    assert.strictEqual(out.visibleText, "hello");
});

t("stray zero-width chars do not produce a bogus signature", () => {
    const out = decodeZeroWidthToSignature("a​b‌c");
    assert.strictEqual(out.sigBuffer, null);
    assert.strictEqual(out.visibleText, "abc");
});

t("payload appended to foreign zero-width noise is rejected, not misread", () => {
    const sig = new Uint8Array(70).fill(3);
    const out = decodeZeroWidthToSignature("​​" + "x" + encodeSignatureToZeroWidth(sig));
    assert.strictEqual(out.sigBuffer, null); // sigLen no longer matches -> refuse
});

t("empty signature is refused at parse time", () => {
    assert.strictEqual(decodeZeroWidthToSignature(encodeSignatureToZeroWidth(new Uint8Array(0))).sigBuffer, null);
});

t("length guard fires", () => {
    const sig = new Uint8Array(100).fill(1);
    const payload = encodeSignatureToZeroWidth(sig, "0011223344556677");
    assert.throws(() => attachPayload("x".repeat(1990), payload), PayloadTooLongError);
    assert.doesNotThrow(() => attachPayload("x".repeat(1500), payload));
});

t("helpers", () => {
    const p = encodeSignatureToZeroWidth(new Uint8Array([1, 2, 3]));
    assert.ok(hasZeroWidthPayload("a" + p));
    assert.ok(!hasZeroWidthPayload("abc"));
    assert.strictEqual(stripZeroWidth("a" + p + "b"), "ab");
});



/* ---- context binding: timestamp carried in the frame ---- */

t("round-trip with a timestamp", () => {
    const sig = new Uint8Array(119).map((_, i) => (i * 13) & 0xff);
    const ts = 1787314443;
    const out = decodeZeroWidthToSignature("coucou" + encodeSignatureToZeroWidth(sig, "0011223344556677", ts));
    assert.strictEqual(out.visibleText, "coucou");
    assert.deepStrictEqual(out.sigBuffer, sig);
    assert.strictEqual(out.timestamp, ts);
    assert.strictEqual(out.keyId, "0011223344556677");
});

t("without a timestamp the field stays absent", () => {
    const out = decodeZeroWidthToSignature(encodeSignatureToZeroWidth(new Uint8Array(40).fill(9), "0011223344556677"));
    assert.strictEqual(out.timestamp, undefined);
    assert.strictEqual(out.sigBuffer.length, 40);
});

t("the timestamp costs exactly 4 bytes", () => {
    const sig = new Uint8Array(119).fill(1);
    const withoutTs = encodeSignatureToZeroWidth(sig, "0011223344556677").length;
    const withTs = encodeSignatureToZeroWidth(sig, "0011223344556677", 1787314443).length;
    assert.strictEqual(withTs - withoutTs, 16); // 4 bytes * 4 characters
});

t("maximum timestamp (year 2106) survives", () => {
    const out = decodeZeroWidthToSignature(encodeSignatureToZeroWidth(new Uint8Array(8).fill(2), undefined, 0xffffffff));
    assert.strictEqual(out.timestamp, 0xffffffff);
});

t("a truncated timestamped frame is rejected", () => {
    const msg = encodeSignatureToZeroWidth(new Uint8Array(64).fill(7), "0011223344556677", 1787314443);
    assert.strictEqual(decodeZeroWidthToSignature(msg.slice(0, msg.length - 20)).sigBuffer, null);
});

const sig = new Uint8Array(119);
console.log(`\npayload: gpg ed25519 signature (119 B) + context -> ${encodeSignatureToZeroWidth(sig, "0011223344556677", 1787314443).length} invisible characters`);
console.log(`${n} tests passed`);
