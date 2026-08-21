# vencord-pgp-signature

A Vencord plugin that signs your Discord messages with OpenPGP and hides the signature inside the
text as invisible characters. The message reads exactly as you wrote it; a badge next to it says
whether it is authentic.

Signing is delegated to `gpg-agent`, so a **YubiKey** — or any hardware OpenPGP key — works: the
private key never leaves the device, and every message asks for a touch.

```
What people see    Hello, this message is signed.   ✓ Verified — Alice
What is sent       Hello, this message is signed.︀︁︂︃… (271 invisible characters)
```

## Try it without installing anything

A demo page signs and verifies in the browser, with a key generated on the spot — open it straight
from disk, everything is bundled, no network calls:

```bash
tools/build-playground.sh && open tools/codec-playground.html
```

It is a build artifact, not committed: it inlines minified openpgp.js so it works without a server,
and it bundles the plugin's *actual* codec rather than a copy, so the demo cannot drift away from
what the plugin does. The sources are `tools/page-body.html` and `tools/page-logic.js`.

## Install

Custom plugins cannot be loaded into a prebuilt Vencord — **the copy VencordInstaller puts on your
machine has its plugin list baked in at build time**. So a third-party plugin like this one means
building Vencord yourself. It is less work than it sounds, and you end up using the same installer
you already know: `pnpm inject` *is* VencordInstaller, just pointed at your own build.

You will need [git](https://git-scm.com), [Node.js](https://nodejs.org),
[pnpm](https://pnpm.io) and **GnuPG**.

### 1. A signing key

Skip if `gpg --list-secret-keys` already shows one.

```bash
gpg --quick-generate-key "Your Name <you@example.org>" ed25519 sign never
```

A YubiKey or any hardware OpenPGP key works too, and is the better option — the private key never
leaves the device and every message asks for a touch.

### 2. Build Vencord with the plugin

```bash
git clone https://github.com/Vendicated/Vencord
cd Vencord
pnpm install --frozen-lockfile
pnpm add openpgp                       # the plugin verifies signatures with it

mkdir -p src/userplugins
cp -r /path/to/vencord-pgp-signature/src/plugins/invisiblePgp src/userplugins/

pnpm build
```

`src/userplugins/` is the directory Vencord reserves for third-party plugins. It does not exist in a
fresh checkout, hence the `mkdir`.

### 3. Point Discord at your build

**Discord Desktop** — run the installer and choose *Install*:

```bash
pnpm inject
```

This is VencordInstaller. If you already installed Vencord with it, this simply replaces that build
with yours; there is nothing to uninstall first.

**Vesktop** — no injection needed. Settings → *Vencord Location* → select the `dist` folder inside
your Vencord checkout.

Then restart Discord fully (quit from the tray, not just close the window).

### 4. Switch it on

1. Discord Settings → **Plugins** → enable **InvisiblePGP**.
2. Right-click any channel or DM → **"Sign messages here."**

That is all the setup there is. `gpg` is located by probing, and the signing key is chosen for you
whenever the choice is unambiguous — a key on a smartcard always wins.

To confirm it works: send a message in that channel and check the badge reads **Verified**, then
edit the message and watch it turn red.

> **Discord Desktop or Vesktop only.** Signing runs `gpg` in Electron's main process, which the
> browser extension has no equivalent of. Verification works everywhere; signing does not.

### Updating

```bash
cd Vencord && git pull && pnpm install --frozen-lockfile
cp -r /path/to/vencord-pgp-signature/src/plugins/invisiblePgp src/userplugins/
pnpm build
```

Re-run `pnpm inject` only if Vencord's own installer version changed.

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
| Encoding | pluggable invisible alphabet — `base16` by default, 4 bits per character |
| Verification | `openpgp.js` in the renderer, loaded lazily |
| Public keys | local keyring → WKD → Keyoxide → keys.openpgp.org → keyserver.ubuntu.com |

What gets signed is not the bare text but a canonical form binding the context:

```
ipgp2 \n <len>:<platform> \n <len>:<channelId> \n <len>:<authorId> \n <len>:<timestamp> \n <len>:<attachment> \n <visible text>
```

Only the timestamp travels inside the payload; the channel and author are read back off the
rendered message, which is exactly what makes a relocated copy fail. Every field is length-prefixed,
so nothing a user controls can shift a boundary.

### Choosing an alphabet

The signature is hidden in a run of invisible codepoints. Three alphabets are available, and all
three are *read* whatever you send with — so changing this never invalidates messages already sent.

| Alphabet | Codepoints | Cost of a 119-byte signature |
|---|---|---|
| `base4` | ZWSP, ZWNJ, ZWJ, WORD JOINER | 541 characters |
| `base16` **(default)** | VS1–VS16 (U+FE00–U+FE0F) | 271 characters |
| `base256` | VS1–VS256 | 136 codepoints, but **259** UTF-16 units |

`base16` halves the cost of `base4` under any counting rule. `base256` halves the *codepoint* count
again, but 240 of its symbols are surrogate pairs, so against Discord's 2000-character limit it
saves only about 4% over `base16` while relying on far more exotic characters. Measure before
switching: `node tools/roundtrip-probe.mjs emit`.

Format specification, including the frame layout and the rules a decoder must enforce:
[`SPEC.md`](SPEC.md). Implementation notes:
[`src/plugins/invisiblePgp/README.md`](src/plugins/invisiblePgp/README.md).

## On a Matrix server

The same signatures can be enforced server-side. [`synapse_module/`](synapse_module/) is a Synapse
module that strips links and media from your own account's messages when they are not validly
signed, and sends you an ntfy alert. Because it runs before the event is persisted, one check covers
every bridge — Instagram, Discord, Signal — with no per-bridge code.

Only messages carrying a link or an attachment need a signature; ordinary conversation is never
touched. Setup is in [`synapse_module/README.md`](synapse_module/README.md).

> **Verification only, for now.** Nothing yet *produces* a signed Matrix message — there is no
> Element plugin and no signing helper. So the module is usable in its default `dry_run` mode, where
> it verifies and alerts but changes nothing, and enforcement (`dry_run: false`) is not usable until
> a signer exists: every link you posted would be stripped, including your own.

## Tests

Everything except the Discord UI can be tested without Discord:

```bash
npm install
npm test            # 217 tests: codec, framing, context binding, verification, key handling
npm run typecheck

tools/test-pgp.sh   # gpg -> codec -> codec -> gpg, all three alphabets, with negative controls

cd synapse_module && pip install -e ".[test]" && pytest -q   # 208 tests
```

Verification is tested against **real** OpenPGP keys, not stubs — a stub would let a signature that
does not actually verify pass the suite. `tests/vectors.json` is run by both the TypeScript and the
Python suite, which is what makes "the two implementations agree" a checkable claim rather than a
hope.

`test-pgp.sh` creates an isolated keyring in `tools/test-gpghome/` when needed. That directory is
**gitignored**: it holds a passphrase-less private key and must never be published.

## Status

Usable, but young.

Covered by tests: the codec and its framing (including property tests over random and deliberately
corrupted input), context binding, every verification verdict against real GnuPG and real
openpgp.js, key resolution and pinning, and the Synapse module end to end.

Checked only by hand: the badge rendering inside Discord.

Not measured yet: which alphabets survive each platform in practice — the table in
[`SPEC.md`](SPEC.md) §7 is still empty. `base16` is the default because it is the conservative
choice, not because `base256` has been ruled out.

## License

GPL-3.0-or-later, same as Vencord.
