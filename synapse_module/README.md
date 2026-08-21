# InvisiblePGP for Synapse

A Synapse module that holds **unsigned links and media from your own account** out of your rooms.

If someone gets into your Matrix account, the first thing they do is post a link. This module makes
that fail: a message from a watched account that contains a URL or an attachment has to carry a
valid OpenPGP signature, or its links and media are stripped and you get an ntfy alert. Ordinary
conversation is never touched.

It runs **inside Synapse**, on the event-persistence path, which means it sees a message before it
is stored and before any bridge picks it up. One check covers Instagram, Discord, Signal and
anything else bridged into the room, with no per-bridge code.

> **This module verifies signatures; it does not create them.** There is no Element plugin and no
> signing helper yet, so nothing currently produces a signed Matrix message. Run it in its default
> `dry_run` mode — it verifies and alerts, and changes nothing. Do not set `dry_run: false` until a
> signer exists, or every link you post will be stripped, your own included.

## What it checks

```
not an m.room.message, or not from a watched account  -> allowed, untouched
carries no link and no media                          -> allowed, untouched   <- the common case
carries a link or media, and is validly signed        -> allowed, untouched
anything else                                         -> alert; strip unless dry_run
```

**Only messages with links or media need a signature.** That is what makes this usable without a
signing client on the Matrix side: you sign the handful of messages that could actually do harm,
not everything you type.

A valid signature has to cover the room, the sender, the moment and — for media — the file itself.
So a genuine message cannot be replayed into another room, backdated, or kept while its attachment
is swapped for something else. The format is specified in [`../SPEC.md`](../SPEC.md).

## Install

```bash
pip install ./synapse_module          # into the same environment as Synapse
```

Create a keyring holding only the public keys of the accounts you are enforcing:

```bash
export GNUPGHOME=/var/lib/synapse/invisible_pgp/gnupg
mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"
gpg --import your-public-key.asc
chown -R synapse:synapse /var/lib/synapse/invisible_pgp
```

Keep it separate from any system keyring. Only keys that belong here should be able to satisfy a
check.

## Configure

```yaml
modules:
  - module: invisible_pgp.SignatureEnforcer
    config:
      gnupg_home: /var/lib/synapse/invisible_pgp/gnupg

      # Start here. Verifies and alerts, but never modifies an event.
      dry_run: true

      identities:
        - mxid: "@me:example.org"
          fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567"

      ntfy:
        url: https://ntfy.sh/your-private-topic
        # token: tk_...
```

| Setting | Default | Meaning |
|---|---|---|
| `gnupg_home` | *required* | Keyring holding the watched accounts' public keys. |
| `identities` | *required* | Accounts to enforce. Each needs an `mxid` and a full 40-character `fingerprint`. |
| `identities[].policy` | `strip` | `strip` removes links and media; `notify_only` alerts and changes nothing. |
| `dry_run` | `true` | When true, nothing is ever modified. |
| `clock_tolerance_sec` | `300` | How far the signing time may sit from the posting time. |
| `gpg_binary` | `gpg` | Path to gpg, if it is not on `PATH`. |
| `gpg_timeout_sec` | `10` | A wedged gpg-agent must not stall event persistence. |
| `ntfy.url` | *none* | Topic to alert. Alerts are off when unset. |
| `ntfy.token` | *none* | Bearer token for a protected topic. |

**`dry_run` ships on.** A bug here silently mangles your real messages, so enforcement has to be
switched on deliberately. Run it against real traffic first, read what it reports, then set
`dry_run: false`.

A short key id is rejected at startup: 16 hex characters is not enough to identify a key safely.

## About bridge ghosts

Someone posting as you on Instagram reaches Synapse as `@instagram_yourname:example.org`, not your
real MXID — so watching only your MXID does not cover a compromised bridged account.

You can list ghosts as identities, but note what that means: **a ghost can never produce a valid
signature**, because nothing on the far side of the bridge can sign. Holding one to `strip` would
eat every link you legitimately post from that account.

Use `policy: notify_only` for ghosts:

```yaml
identities:
  - mxid: "@me:example.org"
    fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567"
  - mxid: "@instagram_me:example.org"
    fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567"
    policy: notify_only
```

You get told when something suspicious appears on the bridged side, without your own Instagram
links being removed.

## What gets stripped

- URLs in `body` are replaced with a visible notice.
- `formatted_body` has its `<a>`, `<img>`, `<video>`, `<audio>`, `<iframe>`, `<embed>` and
  `<object>` tags removed. Anchor *text* is kept — those are your words — while the link goes.
  Both bodies are rewritten; doing only `body` would leave the link live in every client that
  renders HTML, which is most of them.
- `m.image` / `m.video` / `m.audio` / `m.file` become an `m.text` notice with `url`, `file`,
  `info` and every thumbnail reference dropped.
- `m.new_content` is stripped too, so a link cannot reappear through an edit.

## Failure behaviour

- An exception anywhere in the check **allows the event through unchanged**, because a crash here
  would take down message sending for the whole homeserver. Failures are logged.
- A *verification* failure — gpg missing, timing out, unreadable — **blocks**. Failing open there
  would mean a misconfigured gpg quietly switches the feature off.
- ntfy is best effort and never delays or fails an event.

## Limitations

- Signing on Matrix is manual. Nothing here produces signatures; it only checks them.
- End-to-end encrypted rooms are opaque to the homeserver, so nothing can be checked in them.
- A client or bridge that strips invisible characters makes a signed message arrive looking
  unsigned.
- Enforcement covers text, media references and HTML bodies. It does not cover reactions, state
  events or anything a bridge synthesises after the fact.

## Tests

```bash
cd synapse_module
pip install -e ".[test]"
pytest -q
```

The suite signs with a real, throwaway gpg key rather than stubbing crypto — a stub would let a
signature that does not actually verify pass. `tests/test_vectors.py` runs the shared
`tests/vectors.json`, which the TypeScript suite runs too; that file is what makes "the two
implementations agree" a checkable claim.
