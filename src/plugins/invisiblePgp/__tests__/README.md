# Tests

Run from the repository root:

```bash
npm install
npm test          # vitest
npm run typecheck
```

Vitest runs the TypeScript sources directly — there is no build step, and no hand-written stub to
keep in sync. `vitest.config.ts` aliases `@api/DataStore` to `test/stubs/DataStore.ts` so the
modules that persist state are tested exactly as they ship.

| File | What it covers |
|---|---|
| `codec.test.ts` | All three alphabets, the frame, and every way a payload can be rejected. |
| `fuzz.test.ts` | The two properties the scheme rests on, over random input — see below. |
| `binding.test.ts` | The canonical string, and that no field's contents can spoof another's. |
| `verify.test.ts` | Every verdict, end to end, against **real** OpenPGP keys. |
| `trustedSigners.test.ts` | Trust-on-first-use: pin, refresh, mismatch, ignore. |
| `keyResolver.test.ts` | TTL, negative cache, lookup dedup, and the WKD/CRC24 format helpers. |
| `policy.test.ts` | Per-channel signing policy and public-key detection. |
| `vectors.test.ts` | The shared `tests/vectors.json`, which the Python suite runs too. |

## The two properties

`fuzz.test.ts` checks what unit tests cannot: that for *every* input,

1. anything encoded comes back identical, and
2. anything corrupted is **rejected**, never silently decoded into a different valid frame.

The second is the one that matters for security. A codec that quietly turned a damaged payload into
some other well-formed signature would hand an attacker a way to change what gets verified.

The PRNG is seeded and the seed is printed with every assertion, because a fuzz failure nobody can
reproduce is a bug report nobody can act on.

## Why verification is not stubbed

`verify.test.ts` generates real Ed25519 keys and makes real signatures. A stubbed openpgp would let
a signature that does not actually verify pass the suite — which is precisely the bug these tests
exist to catch. Key generation is fast enough to do once per file.

## Beyond the unit tests

```bash
tools/test-pgp.sh          # gpg -> codec -> codec -> gpg, all three alphabets, with negative controls
tools/test-yubikey.sh      # manual: confirms the hardware-key path still signs
cd synapse_module && pytest -q
```
