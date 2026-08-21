"use strict";

/* ---- Codec: faithful port of src/plugins/invisiblePgp/zeroWidth.ts ---- */

const ALPHABET = ["​", "‌", "‍", "⁠"];
const DIGIT_OF = new Map(ALPHABET.map((c, i) => [c, i]));
const MAGIC = 0x01;
const FLAG_HAS_KEY_ID = 1;
const HEADER_LEN = 12;
const DISCORD_MESSAGE_LIMIT = 2000;

function hexToBytes(hex) {
    const out = new Uint8Array(hex.length >> 1);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
}

function bytesToHex(bytes) {
    let out = "";
    for (const b of bytes) out += b.toString(16).padStart(2, "0").toUpperCase();
    return out;
}

function encodeSignatureToZeroWidth(sigBuffer, keyId) {
    const frame = new Uint8Array(HEADER_LEN + sigBuffer.length);
    frame[0] = MAGIC;
    if (keyId && /^[0-9a-fA-F]{16}$/.test(keyId)) {
        frame[1] = FLAG_HAS_KEY_ID;
        frame.set(hexToBytes(keyId), 2);
    }
    frame[10] = (sigBuffer.length >> 8) & 0xff;
    frame[11] = sigBuffer.length & 0xff;
    frame.set(sigBuffer, HEADER_LEN);

    const out = new Array(frame.length * 4);
    let i = 0;
    for (const byte of frame) {
        out[i++] = ALPHABET[(byte >> 6) & 3];
        out[i++] = ALPHABET[(byte >> 4) & 3];
        out[i++] = ALPHABET[(byte >> 2) & 3];
        out[i++] = ALPHABET[byte & 3];
    }
    return out.join("");
}

function decodeZeroWidthToSignature(rawText) {
    const visible = [];
    const digits = [];
    for (const ch of rawText) {
        const d = DIGIT_OF.get(ch);
        if (d === undefined) visible.push(ch);
        else digits.push(d);
    }

    const visibleText = visible.join("");
    if (digits.length === 0 || digits.length % 4 !== 0) return { visibleText, sigBuffer: null };

    const frame = new Uint8Array(digits.length / 4);
    for (let i = 0; i < frame.length; i++) {
        const o = i * 4;
        frame[i] = (digits[o] << 6) | (digits[o + 1] << 4) | (digits[o + 2] << 2) | digits[o + 3];
    }

    if (frame.length < HEADER_LEN || frame[0] !== MAGIC) return { visibleText, sigBuffer: null };
    const sigLen = (frame[10] << 8) | frame[11];
    if (HEADER_LEN + sigLen !== frame.length || sigLen === 0) return { visibleText, sigBuffer: null };

    return {
        visibleText,
        sigBuffer: frame.slice(HEADER_LEN),
        keyId: (frame[1] & FLAG_HAS_KEY_ID) ? bytesToHex(frame.subarray(2, 10)) : undefined
    };
}

/* ---- UI ---- */

const $ = id => document.getElementById(id);
const KEY_STORE = "vc-ipgp-demo-key";

let keys = null; // { privateKey, publicKey, armoredPublic, uid, fingerprint }

function renderReveal(target, text) {
    target.replaceChildren();
    if (!text) { target.textContent = "—"; return; }

    let run = "";
    const flush = () => { if (run) { target.appendChild(document.createTextNode(run)); run = ""; } };

    for (const ch of text) {
        const d = DIGIT_OF.get(ch);
        if (d === undefined) { run += ch; continue; }
        flush();
        const bar = document.createElement("span");
        bar.className = "zw zw" + d;
        bar.title = "U+" + ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
        target.appendChild(bar);
    }
    flush();
}

async function loadKeys(armoredPrivate) {
    const privateKey = await openpgp.readPrivateKey({ armoredKey: armoredPrivate });
    const publicKey = privateKey.toPublic();
    keys = {
        privateKey,
        publicKey,
        armoredPublic: publicKey.armor(),
        uid: (await publicKey.getPrimaryUser()).user.userID?.userID ?? "",
        fingerprint: publicKey.getFingerprint().toUpperCase()
    };

    $("v-key").value = keys.armoredPublic;
    $("key-info").innerHTML = "<span>key <b>" + keys.uid + "</b></span>"
        + "<span>fingerprint <b>" + keys.fingerprint.slice(-16) + "</b></span>"
        + "<span>Ed25519</span>";
}

async function newKey() {
    $("key-info").textContent = "Generating an Ed25519 key…";
    const { privateKey } = await openpgp.generateKey({
        type: "ecc",
        curve: "ed25519",
        userIDs: [{ name: "InvisiblePGP demo", email: "demo@invisiblepgp.test" }],
        format: "armored"
    });
    try { localStorage.setItem(KEY_STORE, privateKey); } catch { /* private mode: the session is enough */ }
    await loadKeys(privateKey);
}

async function sign() {
    const btn = $("s-run");
    btn.disabled = true;
    try {
        const text = $("s-msg").value;
        if (!text.trim()) {
            $("s-meta").innerHTML = "<span style='color: var(--danger)'>The message is empty.</span>";
            return;
        }

        const detached = await openpgp.sign({
            message: await openpgp.createMessage({ text }),
            signingKeys: keys.privateKey,
            detached: true,
            format: "binary"
        });

        const sig = new Uint8Array(detached);
        const payload = encodeSignatureToZeroWidth(sig, keys.fingerprint.slice(-16));

        if (text.length + payload.length > DISCORD_MESSAGE_LIMIT) {
            $("s-meta").innerHTML = "<span style='color: var(--danger)'>Too long: remove "
                + (text.length + payload.length - DISCORD_MESSAGE_LIMIT) + " characters.</span>";
            return;
        }

        const signed = text + payload;
        $("s-out").value = signed;
        renderReveal($("s-reveal"), signed);
        $("s-meta").innerHTML = [
            "signature <b>" + sig.length + " B</b>",
            "<b>" + payload.length + "</b> invisible characters added",
            "total <b>" + signed.length + " / 2000</b>"
        ].map(x => "<span>" + x + "</span>").join("");

        $("v-msg").value = signed;
        await verify();
    } finally {
        btn.disabled = false;
    }
}

async function verify() {
    const verdict = $("v-verdict");
    const meta = $("v-meta");

    const set = (cls, label, detail) => {
        verdict.className = "verdict " + cls;
        verdict.textContent = label;
        meta.innerHTML = (detail ?? []).map(x => "<span>" + x + "</span>").join("");
    };

    const raw = $("v-msg").value;
    if (!raw.trim()) return set("neutral", "Waiting");

    const decoded = decodeZeroWidthToSignature(raw);
    if (!decoded.sigBuffer)
        return set("neutral", "Unsigned", ["No signature hidden in this message."]);

    try {
        const signature = await openpgp.readSignature({ binarySignature: decoded.sigBuffer });
        const publicKey = await openpgp.readKey({ armoredKey: $("v-key").value.trim() });
        const fpr = publicKey.getFingerprint().toUpperCase();
        const uid = (await publicKey.getPrimaryUser()).user.userID?.userID ?? "";

        const packetKeyId = signature.getSigningKeyIDs()[0]?.toHex().toUpperCase();
        if (packetKeyId && !fpr.endsWith(packetKeyId))
            return set("bad", "Key not found", ["signed by <b>" + packetKeyId + "</b>, key given <b>" + fpr.slice(-16) + "</b>"]);

        const result = await openpgp.verify({
            message: await openpgp.createMessage({ text: decoded.visibleText }),
            signature,
            verificationKeys: publicKey,
            expectSigned: true,
            format: "utf8"
        });
        await result.signatures[0].verified;

        set("ok", "Verified \u2014 " + uid.replace(/\s*<[^>]*>\s*/, ""), [
            "fingerprint <b>" + fpr.replace(/(.{4})/g, "$1 ").trim() + "</b>",
            "signature <b>" + decoded.sigBuffer.length + " B</b>"
        ]);
    } catch (e) {
        const msg = String(e.message ?? e);
        if (/digest did not match|verification failed/i.test(msg))
            return set("bad", "Signature broken", ["The message no longer matches its signature."]);
        set("bad", "Error", [msg]);
    }
}

$("s-run").addEventListener("click", sign);
$("s-newkey").addEventListener("click", async () => { await newKey(); await sign(); });
$("v-msg").addEventListener("input", verify);
$("v-key").addEventListener("input", verify);

$("s-copy").addEventListener("click", async () => {
    const btn = $("s-copy");
    if (!$("s-out").value) return;
    try {
        await navigator.clipboard.writeText($("s-out").value);
        btn.textContent = "Copied";
    } catch {
        btn.textContent = "Copy blocked";
    }
    setTimeout(() => { btn.textContent = "Copy"; }, 1600);
});

/* A key is ready the moment the page opens: nothing to configure. */
(async () => {
    let stored = null;
    try { stored = localStorage.getItem(KEY_STORE); } catch { /* storage unavailable */ }

    if (stored) {
        try { await loadKeys(stored); } catch { await newKey(); }
    } else {
        await newKey();
    }
    await sign();
})();
