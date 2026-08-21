# Tests

Vencord ships no test runner. These modules are dependency-free, so node alone is enough — build
them next to the tests, then run them.

## Zero-width codec

```bash
npx esbuild ../zeroWidth.ts --format=esm --outfile=zeroWidth.mjs
node zeroWidth.test.mjs
```

Covered: round-trip (all 256 byte values, non-ASCII text), unsigned messages, truncated payloads,
stray zero-width characters, empty signatures, the 2000-character guard, and the context timestamp
carried in the frame.

## Channel policy and public key detection

`channelPolicy.ts` reaches for Vencord's DataStore, so it needs a stub:

```bash
printf 'const m=new Map();export const get=async k=>m.get(k);export const set=async(k,v)=>void m.set(k,v);\n' > datastore-stub.mjs
npx esbuild ../publicKeyDetection.ts --format=esm --outfile=publicKeyDetection.mjs
npx esbuild ../channelPolicy.ts --bundle --format=esm --platform=node \
    --alias:@api/DataStore=./datastore-stub.mjs --outfile=channelPolicy.mjs
node policy.test.mjs
```

Covered: inline armored key detection (and rejection of unterminated or private-key blocks),
attachment picking with a size cap, and the per-channel signing policy defaulting to off.

The built `.mjs` files are gitignored.
