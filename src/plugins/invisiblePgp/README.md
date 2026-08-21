# InvisiblePGP

Detached OpenPGP signatures, hidden inside the message as invisible characters.

## Install

Custom plugins need a Vencord built from source — a prebuilt one has its plugin list fixed at build
time. Full walkthrough in the [repository README](../../../README.md#install); the short version:

```bash
git clone https://github.com/Vendicated/Vencord
cd Vencord && pnpm install --frozen-lockfile && pnpm add openpgp
mkdir -p src/userplugins
cp -r <this-folder> src/userplugins/invisiblePgp
pnpm build && pnpm inject            # Discord Desktop or Vesktop is required to sign
```

`src/userplugins/` is the directory Vencord reserves for third-party plugins; it is absent from a
fresh checkout.

Then, in Discord, right-click a channel or a DM and pick **"Sign messages here"**. Signing is off
everywhere until you do that, per conversation.

Everything else configures itself at startup: the `gpg` binary is located by probing (PATH first,
then the default Gpg4win and Homebrew install locations), and the signing key is picked without
asking whenever the choice is unambiguous — a key on a smartcard always wins, since that is the one
you plugged in on purpose. The "gpg path" and "signing key" fields exist only to override this.

## Where signing is on

Signing is opt-in **per channel**, never global. A signature is permanent, transferable proof of
what you wrote (see "What this does not do" below), so it belongs on the conversations you picked,
not on everything you type. The list of enabled channels lives in `channelPolicy.ts` and is
reviewable in the settings.

The plugin never switches signing on by itself. When someone shares a public key — inline, or as a
`.asc` / `.gpg` / `.pgp` / `.key` attachment — a small card appears under their message offering to
**add the key to your keyring** and to **start signing in that conversation**. Both are buttons.
Detection is local and synchronous: an attachment is recognised by its name, and only downloaded
(with a 256 KB cap) once you press the button.

## How it works

| | |
|---|---|
| Signing | `gpg --detach-sign` in Electron's main process → `gpg-agent` → YubiKey touch/PIN |
| Encoding | `base16` over VS1–VS16 by default; `base4` and `base256` also available |
| Verification | `openpgp.js`, in the renderer, loaded lazily |
| Public keys | local keyring (DataStore) → WKD → Keyoxide → keys.openpgp.org → keyserver.ubuntu.com |

A real Ed25519 signature from gpg is **119 bytes** — OpenPGP packet included — which comes to
**271 invisible characters** in `base16` with context binding. The plugin refuses to send past
Discord's 2000 character limit and says how many characters to cut.

### Payload frame

```
v2:  magic(1)=0x02 | flags(1) | [keyId(8)] | [timestamp(4)] | sigLen(2, BE) | detached signature
v1:  magic(1)=0x01 | flags(1) |  keyId(8)  | [timestamp(4)] | sigLen(2, BE) | detached signature
```

Optional fields are present only when their flag bit is set; v1 reserved the key-id bytes
unconditionally, which v2 stopped doing. v1 frames are still read, so messages signed before the
change keep verifying.

Three checks keep a stray invisible character — from another plugin, or a copy-paste — from being
read as a signature: the magic byte, `sigLen == remainder`, and rejecting any flag bit that has no
meaning. That last one also means each frame has exactly one byte representation, so a relay cannot
reword one without changing what it decodes to.

### Why decoding is careful about emoji

The payload is a **contiguous run at the very end** of the message, preceded by a U+034F anchor —
never "every alphabet character wherever it appears". U+FE0F is both a `base16` symbol and the emoji
presentation selector, so a global strip would quietly rewrite any `❤️` (U+2764 U+FE0F) you actually
typed. If the trailing run does not parse as a frame, the message is returned **untouched**.

Full format: [`../../../SPEC.md`](../../../SPEC.md).

## Context binding

Signing the text alone authenticates *what* was said, not *where*, *when*, or *by whom*. A genuinely
signed message can be copied into another channel, where it verifies perfectly and reads as if it
had been written there. So the plugin signs a canonical form (`binding.ts`):

```
ipgp2 \n <len>:<platform> \n <len>:<conversationId> \n <len>:<authorId> \n <len>:<timestamp> \n <len>:<attachment> \n <visible text>
```

Every field before the text is length-prefixed (UTF-8 bytes), so no user content can inject a
delimiter and shift the boundaries — and the free-form text comes last, where it cannot shift one
either. `platform` is bound too, so a Discord signature cannot be replayed on Matrix.

The earlier `ipgp1` form relied on every field being digits-only, which held for Discord snowflakes
but not for Matrix ids like `!room:server`. It is still accepted for v1 frames, never emitted.

Only the timestamp travels in the payload (4 bytes). The channel and author are read back off the
rendered message — which is exactly what makes a relocated copy fail to reproduce the signed string.
Verification also compares the signed timestamp against the one Discord recorded, within a
configurable clock tolerance (5 minutes by default).

What this closes: a signed message replayed into another channel, under another author, or hours
later. What it does not close: fake screenshots, nor the absence of a signature — a signature is
positive proof, never proof of absence.

## Expected signers

`trustedSigners.ts` is what makes a missing signature mean something. Enrolment is trust-on-first-
use: the first valid signature seen from an account pins its key. From then on an unsigned message
from that account is flagged, and a message signed by a *different* key is flagged too, so an
attacker cannot quietly enrol their own key over an existing one.

Automatic pinning can be turned off, and the list is editable by hand in the settings.

## Files

| File | Role |
|---|---|
| `index.tsx` | plugin definition, send listener, message decoration |
| `native.ts` | main process: gpg detection, `spawn(gpg)`, YubiKey timeout, `--with-colons` parsing |
| `native.bridge.ts` | renderer-side view of the native module; degrades cleanly off Desktop |
| `codec.ts` | the three invisible alphabets, the frame, and the trailing-run rules |
| `binding.ts` | canonical signed form: platform + conversation + author + timestamp + attachment + text |
| `channelPolicy.ts` | which channels signing is switched on for |
| `publicKeyDetection.ts` | spotting a shared public key, inline or as an attachment |
| `trustedSigners.ts` | pinned keys per account, trust-on-first-use, key substitution checks |
| `verify.ts` | openpgp.js, context checks, per-message cache, deduplicated verifications |
| `keyResolver.ts` | DataStore keyring, WKD (z-base-32/SHA-1), negative cache |
| `components/` | inline badge, public key offer card, settings UI |

## Test benches (`tools/`, outside Vencord)

| | |
|---|---|
| `test-pgp.sh` | the full chain: gpg signs → codec → decode → gpg re-verifies, plus a negative control |
| `verify-openpgp.mjs` | the plugin's real inbound path, verified by openpgp.js |
| `build-playground.sh` | builds `codec-playground.html`: sign and verify in the browser |
| `roundtrip-probe.mjs` | emits one probe per alphabet, then reports which survived a real platform |
| `gen-vectors.mts` | regenerates `tests/vectors.json`, the cross-language contract |
| `test-gpghome/` | isolated keyring holding an Ed25519 test key (`rm -rf` to wipe it) |
| `test-yubikey.sh` | the same, against Windows gpg and a physical YubiKey |

Every one of these bundles the real modules rather than a copy, so a bench cannot pass while the
plugin is broken.

## Handled errors

`NO_GPG`, `KEY_NOT_FOUND`, `CARD_REMOVED`, `BAD_PIN`, `TOUCH_TIMEOUT` (SIGTERM then SIGKILL, and the
promise resolves immediately rather than waiting for the process to die), message too long, public
key not found, broken signature, message edited after signing, message out of context.

The seven badge verdicts: `VALID`, `INVALID`, `REPLAYED`, `MISSING_SIGNATURE`, `KEY_CHANGED`,
`UNKNOWN_KEY`, `UNSIGNED` (plus `ERROR`). `INVALID` covers edited text and a relocated message
indiscriminately — both simply fail to reproduce the signed string, and nothing distinguishes them
cryptographically. `REPLAYED` is reserved for the one decidable case: timestamp drift.

Failure behaviour is configurable: **fail-closed** (send cancelled, the default) or fail-open (the
message goes out in the clear).

## What this does not do

A signature is positive proof: it establishes what you *did* write, never what you did not. It is
also **transferable** — whoever holds a signed message can prove its authorship to anyone else,
forever, out of context. That is the opposite of what Signal and OTR provide, where per-message
authentication is symmetric and therefore deniable.

This is why signing is per-channel and off by default: sign what you would want to be able to
prove, not your everyday conversation.

## Known limitations

- On Discord the signature covers the **visible text only**: not attachments, not embeds. (On
  Matrix the media reference *is* bound — see [`../../../SPEC.md`](../../../SPEC.md) §5.)
- A client that strips invisible characters (some bots, IRC bridges) breaks the signature;
  the message stays readable and the badge turns red.
- `renderMessageDecoration` is a recent Vencord API. On a fork that does not expose it, swap in
  `renderMessageAccessory` (badge shown below the message) in `index.tsx`.
- Trust-on-first-use has the usual blind spot: if the first signed message you ever see from someone
  is already an attacker's, it is their key that gets pinned. Import keys by hand for people who
  matter.
