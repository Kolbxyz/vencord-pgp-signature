# InvisiblePGP

Detached OpenPGP signatures, hidden inside the message as zero-width characters.

## Install

```bash
git clone https://github.com/Vendicated/Vencord
cd Vencord && pnpm i && pnpm add openpgp
cp -r <this-folder> src/plugins/invisiblePgp
pnpm build --dev && pnpm inject      # Vencord Desktop is required to sign
```

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
| Encoding | base-4 over ZWSP / ZWNJ / ZWJ / WORD JOINER, 2 bits per character |
| Verification | `openpgp.js`, in the renderer, loaded lazily |
| Public keys | local keyring (DataStore) → WKD → Keyoxide → keys.openpgp.org → keyserver.ubuntu.com |

A real Ed25519 signature from gpg is **119 bytes** — OpenPGP packet included — which comes to
**540 invisible characters** with context binding. The plugin refuses to send past Discord's 2000
character limit and says how many characters to cut.

### Payload frame

```
magic(1) | flags(1) | keyId(8) | [timestamp(4)] | sigLen(2, big-endian) | detached signature
```

The timestamp is present only when the `HAS_CONTEXT` flag bit is set.

The magic byte and the `sigLen == remainder` check are what keep a stray zero-width character —
from another plugin, or a copy-paste — from being read as a signature.

## Context binding

Signing the text alone authenticates *what* was said, not *where*, *when*, or *by whom*. A genuinely
signed message can be copied into another channel, where it verifies perfectly and reads as if it
had been written there. So the plugin signs a canonical form (`binding.ts`):

```
ipgp1 \n <channelId> \n <authorId> \n <unix timestamp> \n <visible text>
```

The free-form text comes last and every field before it is digits only: no user content can inject
a delimiter and shift the field boundaries.

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
| `zeroWidth.ts` | `encodeSignatureToZeroWidth` / `decodeZeroWidthToSignature`, frame, length guard |
| `binding.ts` | canonical signed form: channel + author + timestamp + text |
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
| `codec-playground.html` | web page: sign and verify in the browser |
| `test-gpghome/` | isolated keyring holding an Ed25519 test key (`rm -rf` to wipe it) |
| `test-yubikey.sh` | the same, against Windows gpg and a physical YubiKey |

The scripts transpile `zeroWidth.ts` on the fly: they test the source, not a copy of it.

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

- The signature covers the **visible text only**: not attachments, not embeds.
- A client that strips zero-width characters (some bots, Matrix/IRC bridges) breaks the signature;
  the message stays readable and the badge turns red.
- `renderMessageDecoration` is a recent Vencord API. On a fork that does not expose it, swap in
  `renderMessageAccessory` (badge shown below the message) in `index.tsx`.
- Trust-on-first-use has the usual blind spot: if the first signed message you ever see from someone
  is already an attacker's, it is their key that gets pinned. Import keys by hand for people who
  matter.
