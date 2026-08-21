# InvisiblePGP wire format

This is the contract between implementations. It exists because the format now has two of them —
the Vencord plugin (TypeScript) and the Synapse module (Python) — and "they agree" has to mean
something checkable rather than something believed.

`tests/vectors.json` is the executable half of this document. Both suites read it; a change that
breaks agreement turns exactly one of them red. Regenerate it with `npm run vectors` and read the
diff before committing.

---

## 1. Overview

A message carries a **detached OpenPGP signature** hidden in a run of invisible codepoints appended
to its text. The signature covers a **canonical string** that binds the message to a conversation,
an author and a moment — not the bare text, so a genuine message cannot be lifted somewhere else
and still verify.

```
<visible text><anchor><payload run>
                      └─ frame ─┘  encoded in one of three alphabets
```

## 2. Alphabets

| Name | Codepoints | Bits per codepoint | UTF-16 units per symbol |
|---|---|---|---|
| `base4` | U+200B, U+200C, U+200D, U+2060 | 2 | 1 |
| `base16` | U+FE00–U+FE0F (VS1–VS16) | 4 | 1 |
| `base256` | U+FE00–U+FE0F, U+E0100–U+E01EF (VS1–VS256) | 8 | 1 or 2 |

Bytes are encoded most-significant-bits first. A symbol's index in its alphabet *is* its digit.

`base16` is a strict subset of `base256`, so **a run cannot identify its own alphabet**. Decoders
resolve it by trial: decode the run under every alphabet, keep the readings that yield a valid
frame, and accept only if **exactly one** does. Two readings of the same run is not a verdict that
can be defended, so it is not one that gets returned.

### Cost

For a 119-byte Ed25519 signature plus its header:

| Alphabet | Codepoints | UTF-16 units |
|---|---|---|
| `base4` | 541 | 541 |
| `base16` | 271 | 271 |
| `base256` | 136 | 259 |

(Measured with `tools/roundtrip-probe.mjs emit`; the extra codepoint over the theoretical figure is
the anchor, and `base256`'s header is one byte shorter because it carries no key-id padding.)

Note what the last row actually says: `base256` uses **half** the codepoints of `base16` but only
about 4% fewer UTF-16 units, because 240 of its 256 symbols are surrogate pairs. If a platform
counts UTF-16 units — as Discord's 2000-character limit does — `base256` buys almost nothing over
`base16` while relying on far more exotic codepoints. That is why `base16` is the default.

`base16` is an unambiguous 2× improvement on `base4` under any counting rule. `base256` is 4× by
codepoint, but 240 of its symbols are astral and cost two UTF-16 units, so whether it actually wins
depends on how a platform counts. **That is a measurement, not a theory** — see §7.

## 3. Anchor

The payload run is preceded by **U+034F COMBINING GRAPHEME JOINER**.

A variation selector modifies the character it follows, and U+FE0F is the emoji presentation
selector. Without an anchor, appending a `base16` payload to a message ending in `👍` could change
how that character renders. U+034F is defined to have no visible effect and belongs to no alphabet
here, so it gives the first selector a harmless base character and marks where the run begins.

The anchor is **optional on decode**: legacy v1 messages predate it, and a platform that strips
U+034F still leaves a decodable payload.

## 4. Frame

```
v2:  magic(1)=0x02 | flags(1) | [keyId(8)] | [timestamp(4) BE] | sigLen(2 BE) | signature
v1:  magic(1)=0x01 | flags(1) |  keyId(8)  | [timestamp(4) BE] | sigLen(2 BE) | signature
```

| Flag | Bit | Meaning |
|---|---|---|
| `HAS_KEY_ID` | 0 | The 8 key-id bytes are present (v2). In v1 they are always reserved. |
| `HAS_CONTEXT` | 1 | A timestamp is present, and the signature covers the context binding. |

Rules a decoder **must** enforce:

- Reject any magic byte other than `0x01` or `0x02`.
- Reject any flag bit outside those two. Unused bits are rejected rather than ignored so that each
  frame has exactly one byte representation — otherwise two different payloads could decode to the
  same signature, and a relay could reword one without detection.
- Reject `sigLen == 0`, and reject any frame where the header length plus `sigLen` is not exactly
  the frame length. This is what stops a run padded with stray invisible characters from being read
  as a shorter, valid signature.
- Reject a v1 frame that was not written in `base4`. v1 is base4 by definition.

`keyId` is 16 uppercase hex characters, the last 8 bytes of the fingerprint. It is a **hint for key
lookup only**. It is attacker-controlled, so a verifier that finds it disagreeing with the key id in
the signature packet must reject the message rather than quietly trust the packet.

## 5. Canonical signed string

### v2 — `ipgp2`, used with frame v2

```
ipgp2\n
<byteLen>:<platform>\n
<byteLen>:<conversationId>\n
<byteLen>:<authorId>\n
<byteLen>:<timestamp>\n
<byteLen>:<attachment>\n
<visibleText>
```

- `platform` is `discord` or `matrix`. It is bound so a Discord signature cannot be replayed on
  Matrix.
- `conversationId` is the channel id (Discord) or room id (Matrix).
- `authorId` is the user id (Discord) or MXID (Matrix).
- `timestamp` is unix seconds, decimal, as chosen by the sender's clock.
- `attachment` is the media reference — the `mxc://` URI on Matrix, or `""` when there is none.
  Without it a signature over an image would cover only its filename, so a captured signed message
  could keep its signature while pointing at different content.
- `visibleText` is the message with the payload run removed.

**Lengths are UTF-8 byte counts**, not codepoint counts, so implementations in different languages
agree exactly. Length-prefixing is what makes the encoding injection-proof: under v1 an id
containing a newline could shift every later field. The free-form text stays last and unprefixed,
where it cannot shift a boundary.

### v1 — `ipgp1`, used with frame v1

```
ipgp1\n<channelId>\n<authorId>\n<timestamp>\n<visibleText>
```

Discord only, and safe there solely because every field was validated as digits. Retained so
signatures made before the change keep verifying; never emitted.

## 6. Decoding a message

1. Walk backwards from the end while the character belongs to *any* alphabet. That run is the
   candidate payload.
2. If the character before the run is U+034F, consume it too.
3. Decode the run under each alphabet; parse each result as a frame; keep the valid ones.
4. Accept only if exactly one alphabet yields a valid frame. Otherwise treat the message as
   unsigned.
5. **If there is no valid payload, return the message unchanged.**

Step 5 is not a detail. Decoders must **not** strip alphabet characters globally: U+FE0F is part of
`base16` *and* is the emoji presentation selector, so a global strip silently rewrites any `❤️`
(U+2764 U+FE0F) a user actually typed. Only a contiguous run at the very end can be a payload,
because that is the only place one is ever written.

## 7. Choosing an alphabet

The default is `base16`: an unambiguous improvement on `base4`, entirely within the BMP, and far
less exotic than 240 astral codepoints.

`base256` is offered but not default. Before switching, measure it — `tools/roundtrip-probe.mjs`
emits one probe message per alphabet and reads them back. Record real results here:

| Platform | base4 | base16 | base256 |
|---|---|---|---|
| Discord (desktop) | not yet measured | not yet measured | not yet measured |
| Discord (web) | not yet measured | not yet measured | not yet measured |
| Discord (mobile) | not yet measured | not yet measured | not yet measured |
| Synapse + Element | not yet measured | not yet measured | not yet measured |
| Synapse + a bridge | not yet measured | not yet measured | not yet measured |

Decoders accept all three regardless of which one is being emitted, so changing the default never
invalidates messages already sent.

## 8. What this format does not do

- It authenticates the **text**, and on Matrix the media reference. It does not cover Discord
  attachments, embeds, reactions or edits made by the platform.
- It is not confidentiality. Everything remains in plain sight; only the signature is hidden.
- It does not survive a client or bridge that strips invisible characters. Where that happens, a
  signed message arrives looking unsigned.
- A signature is **transferable, non-repudiable proof** that you wrote something. That is the point,
  and it is also the risk — which is why signing is opt-in per conversation.
