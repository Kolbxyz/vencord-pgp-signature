import assert from "assert";
import { findPublicKeyBlock, findKeyAttachment, MAX_KEY_BYTES } from "./publicKeyDetection.mjs";
import { loadChannelPolicy, isChannelSigned, setChannelSigned, toggleChannelSigned, getSignedChannels } from "./channelPolicy.mjs";

let n = 0, fails = 0;
const t = (name, fn) => {
    try { fn(); n++; console.log("  ok   " + name); }
    catch (e) { fails++; console.log("  FAIL " + name + "\n         " + e.message); }
};
const ta = async (name, fn) => {
    try { await fn(); n++; console.log("  ok   " + name); }
    catch (e) { fails++; console.log("  FAIL " + name + "\n         " + e.message); }
};

const KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZ...\n-----END PGP PUBLIC KEY BLOCK-----";

t("inline armored key is found", () => {
    assert.strictEqual(findPublicKeyBlock("here is my key\n" + KEY + "\nthanks"), KEY);
});
t("plain message yields nothing", () => {
    assert.strictEqual(findPublicKeyBlock("just talking about pgp public key blocks"), null);
});
t("unterminated block is rejected", () => {
    assert.strictEqual(findPublicKeyBlock("-----BEGIN PGP PUBLIC KEY BLOCK-----\nmDME"), null);
});
t("a private key block is not treated as public", () => {
    assert.strictEqual(findPublicKeyBlock("-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK-----"), null);
});
t("empty content is safe", () => {
    assert.strictEqual(findPublicKeyBlock(undefined), null);
    assert.strictEqual(findPublicKeyBlock(""), null);
});

t(".asc attachment is picked", () => {
    const a = findKeyAttachment([{ filename: "photo.png", url: "u", size: 10 }, { filename: "alice.asc", url: "u2", size: 3000 }]);
    assert.strictEqual(a?.filename, "alice.asc");
});
t("oversized key file is refused", () => {
    assert.strictEqual(findKeyAttachment([{ filename: "huge.asc", url: "u", size: MAX_KEY_BYTES + 1 }]), null);
});
t("attachment without url is refused", () => {
    assert.strictEqual(findKeyAttachment([{ filename: "alice.asc", size: 10 }]), null);
});
t("unrelated attachments yield nothing", () => {
    assert.strictEqual(findKeyAttachment([{ filename: "notes.txt", url: "u", size: 10 }]), null);
    assert.strictEqual(findKeyAttachment(undefined), null);
});

await ta("signing is off everywhere by default", async () => {
    await loadChannelPolicy();
    assert.strictEqual(isChannelSigned("111"), false);
    assert.deepStrictEqual(getSignedChannels(), {});
});
await ta("a channel can be switched on and off", async () => {
    await setChannelSigned("111", true);
    assert.strictEqual(isChannelSigned("111"), true);
    assert.strictEqual(isChannelSigned("222"), false, "enabling one channel must not enable others");
    await setChannelSigned("111", false);
    assert.strictEqual(isChannelSigned("111"), false);
});
await ta("toggle returns the new state", async () => {
    assert.strictEqual(await toggleChannelSigned("333"), true);
    assert.strictEqual(await toggleChannelSigned("333"), false);
});

console.log(fails ? `\n${fails} failure(s)` : `\n${n} tests passed`);
process.exit(fails ? 1 : 0);
