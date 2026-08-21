"use strict";

/* ---- Codec ----
 *
 * The real thing, bundled from src/plugins/invisiblePgp/ by build-playground.sh and exposed as
 * `globalThis.ipgp`. It used to be a hand-copied port, which drifted the moment the format
 * changed — a demo that quietly disagrees with the plugin is worse than no demo.
 */

const { BASE4, BASE16, BASE256, DISCORD_MESSAGE_LIMIT, alphabetByName, decodeMessage, encodePayload }
    = globalThis.ipgp;
const { canonicalSignedText } = globalThis.ipgp;

/** The demo stands in for one Discord channel, so signatures are bound to a fixed context. */
const DEMO_CONTEXT = {
    platform: "discord",
    conversationId: "1234567890123456789",
    authorId: "9876543210987654321"
};

const selectedAlphabet = () => alphabetByName($("s-alphabet")?.value ?? "base16");

/** Every alphabet symbol, mapped to a colour bucket for the reveal view. */
const SYMBOL_CLASS = new Map();
for (const [bucket, alphabet] of [BASE4, BASE16, BASE256].entries())
    for (const symbol of alphabet.symbols) if (!SYMBOL_CLASS.has(symbol)) SYMBOL_CLASS.set(symbol, bucket);

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
        const bucket = SYMBOL_CLASS.get(ch);
        if (bucket === undefined) { run += ch; continue; }
        flush();
        const bar = document.createElement("span");
        bar.className = "zw zw" + bucket;
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

        // What actually gets signed is the context binding, not the bare text — exactly as the
        // plugin does it, which is what makes the "copy it elsewhere" demo below fail honestly.
        const signedAt = Math.floor(Date.now() / 1000);
        const ctx = { ...DEMO_CONTEXT, timestamp: signedAt };

        const detached = await openpgp.sign({
            message: await openpgp.createMessage({ text: canonicalSignedText(ctx, text) }),
            signingKeys: keys.privateKey,
            detached: true,
            format: "binary"
        });

        const sig = new Uint8Array(detached);
        const payload = encodePayload(sig, selectedAlphabet(), keys.fingerprint.slice(-16), signedAt);

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
            "<b>" + [...payload].length + "</b> codepoints added "
                + "(<b>" + payload.length + "</b> UTF-16 units, " + selectedAlphabet().name + ")",
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

    const decoded = decodeMessage(raw);
    if (!decoded.frame)
        return set("neutral", "Unsigned", ["No signature hidden in this message."]);

    try {
        const signature = await openpgp.readSignature({ binarySignature: decoded.frame.sig });
        const publicKey = await openpgp.readKey({ armoredKey: $("v-key").value.trim() });
        const fpr = publicKey.getFingerprint().toUpperCase();
        const uid = (await publicKey.getPrimaryUser()).user.userID?.userID ?? "";

        const packetKeyId = signature.getSigningKeyIDs()[0]?.toHex().toUpperCase();
        if (packetKeyId && !fpr.endsWith(packetKeyId))
            return set("bad", "Key not found", ["signed by <b>" + packetKeyId + "</b>, key given <b>" + fpr.slice(-16) + "</b>"]);

        // Rebuild exactly what was signed. Without the timestamp the payload predates context
        // binding and only covers the bare text.
        const signedText = decoded.frame.timestamp === undefined
            ? decoded.visibleText
            : canonicalSignedText({ ...DEMO_CONTEXT, timestamp: decoded.frame.timestamp }, decoded.visibleText);

        const result = await openpgp.verify({
            message: await openpgp.createMessage({ text: signedText }),
            signature,
            verificationKeys: publicKey,
            expectSigned: true,
            format: "utf8"
        });
        await result.signatures[0].verified;

        set("ok", "Verified \u2014 " + uid.replace(/\s*<[^>]*>\s*/, ""), [
            "fingerprint <b>" + fpr.replace(/(.{4})/g, "$1 ").trim() + "</b>",
            "signature <b>" + decoded.frame.sig.length + " B</b>",
            "alphabet <b>" + decoded.alphabet.name + "</b>"
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
$("s-alphabet").addEventListener("change", sign);

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
