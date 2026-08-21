# Zero-width codec tests

Vencord ships no test runner. The codec is dependency-free TypeScript, so node alone is enough:

```bash
npx esbuild ../zeroWidth.ts --format=esm --outfile=zeroWidth.mjs
node zeroWidth.test.mjs
```

Covered: round-trip (including all 256 byte values and non-ASCII text), unsigned messages, truncated
payloads, stray zero-width characters, empty signatures, the 2000-character guard, and the context
timestamp carried in the frame.
