# vencord-pgp-signature

A Vencord plugin that signs your Discord messages with OpenPGP and hides the signature inside the
text as invisible characters. The message reads exactly as you wrote it; a badge next to it says
whether it is authentic.

Signing is delegated to `gpg-agent`, so a **YubiKey** — or any hardware OpenPGP key — works: the
private key never leaves the device, and every message asks for a touch.

```
What people see    Hello, this message is signed.   ✓ Verified — Alice
What is sent       Hello, this message is signed.​‌‍⁠​‌… (540 invisible characters)
```

## Try it without installing anything

A demo page signs and verifies in the browser, with a key generated on the spot:
[**tools/codec-playground.html**](tools/codec-playground.html) — open it straight from disk,
everything is bundled, no network calls.

That file is a build artifact: it inlines minified openpgp.js so it works without a server. The
sources are `tools/page-body.html` and `tools/page-logic.js`, and `tools/build-playground.sh`
regenerates it.

## Install

```bash
git clone https://github.com/Vendicated/Vencord
cd Vencord && pnpm i && pnpm add openpgp
cp -r <this-repo>/src/plugins/invisiblePgp src/plugins/
pnpm build --dev && pnpm inject      # Vencord Desktop is required to sign
```

In Discord, right-click a channel or a DM and pick **"Sign messages here"**. That is the only thing
you have to do — `gpg` is located by probing, and the signing key is picked automatically whenever
the choice is unambiguous (a key on a smartcard always wins).

## Signing is per conversation

Signing is off everywhere until you switch it on for a specific channel or DM, and it is never
global. That is deliberate, and the reason is in the next section: a signature is permanent,
transferable proof of what you wrote, so it belongs on the conversations you chose.

The plugin never enables anything on its own. When someone shares a public key — inline or as a
`.asc` attachment — a card appears under their message offering to add the key to your keyring and
to start signing in that conversation. Both are buttons; nothing is downloaded or imported until
you press one.

## What this does and does not protect against

This is the part that matters. A signature is **positive proof**: it establishes what someone *did*
write. It can never establish what they did *not* write.

**It works against:**

- **tampering** with a signed message — change one character and the badge turns red;
- **impersonation** — an attacker cannot produce a valid signature without the private key;
- **replay** — a genuinely signed message copied into another channel, attributed to another author,
  or reposted hours later is flagged, because the signature covers the channel, the author and a
  timestamp, not just the text;
- **key substitution** — once an account has signed, its key is pinned; a later message signed by a
  different key is flagged rather than silently accepted.

**It does not work against:**

- **fake screenshots.** An image contains no invisible characters. This is the most common way to
  put words in someone's mouth, and there is no cryptographic answer to it here;
- **missing signatures in general.** An unsigned message from a stranger proves nothing either way.
  The plugin only fixes this for accounts it has seen sign — see below;
- **clients that strip invisible characters** (some bots, Matrix/IRC bridges): the message stays
  readable, but the signature is lost and the badge turns red.

And one consequence to accept: signing makes your messages **non-repudiable**. Signal and OTR
authenticate messages too, but symmetrically — your correspondent knows it is you, and can prove it
to nobody, because they could have forged the whole transcript themselves. A PGP signature is
asymmetric: whoever holds the message can prove its authorship to any third party, forever, out of
context. Context binding sharpens that proof rather than softening it — it pins the channel and the
minute as well as the text.

Revoking or deleting your key does not undo it: revocation signals distrust going forward, it does
not invalidate past signatures. This is why signing is per-channel and off by default. Sign what you
would want to be able to prove.

## Expected signers

This is what makes a missing signature meaningful. As soon as an account produces a valid signature,
its key is pinned. From then on:

| What you see | What it means |
|---|---|
| ✓ **Verified — Alice** | valid signature, pinned key, right channel, right moment |
| ⚠ **Unsigned — signature expected** | this account normally signs, and this message is not signed |
| ⚠ **Different key** | valid signature, but not the key pinned for this account |
| ⚠ **Signature broken** | text was edited, or the message was copied from somewhere else |
| ⚠ **Out of context** | signed for a different moment than when it was posted |
| ? **Key not found** | signed, but no public key could be resolved |
| *Unsigned* | unknown account, nothing expected — discreet, and can be hidden |

Automatic pinning can be turned off, and the list is editable by hand in the settings.

Worth knowing: trust-on-first-use has the usual blind spot. If the very first signed message you see
from someone is already an attacker's, it is their key that gets pinned. For people who really
matter, import their public key by hand.

## How it works

| | |
|---|---|
| Signing | `gpg --detach-sign` in Electron's main process → `gpg-agent` → YubiKey |
| Encoding | base-4 over ZWSP / ZWNJ / ZWJ / WORD JOINER, 2 bits per character |
| Verification | `openpgp.js` in the renderer, loaded lazily |
| Public keys | local keyring → WKD → Keyoxide → keys.openpgp.org → keyserver.ubuntu.com |

What gets signed is not the bare text but a canonical form binding the context:

```
ipgp1 \n <channelId> \n <authorId> \n <unix timestamp> \n <visible text>
```

Only the timestamp travels inside the payload (4 bytes); the channel and author are read back off
the rendered message, which is exactly what makes a relocated copy fail. A gpg Ed25519 signature is
119 bytes, so **540 invisible characters** — well under Discord's 2000 character limit.

Frame format, implementation notes and limitations:
[`src/plugins/invisiblePgp/README.md`](src/plugins/invisiblePgp/README.md).

## Tests

The codec, the native bridge and verification can all be tested without Discord:

```bash
cd tools && npm install
./test-pgp.sh                                    # gpg → zero-width → gpg, with a negative control
node ../src/plugins/invisiblePgp/__tests__/zeroWidth.test.mjs
```

`test-pgp.sh` creates an isolated keyring in `tools/test-gpghome/` when needed. That directory is
**gitignored**: it holds a passphrase-less private key and must never be published.

## Status

Usable, but young. The codec, the `gpg` bridge, context binding and key pinning are covered by tests
run against real GnuPG and real openpgp.js. The badge rendering inside Discord has only been checked
by hand.

## License

GPL-3.0-or-later, same as Vencord.
