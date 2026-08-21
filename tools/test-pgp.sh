#!/usr/bin/env bash
# The plugin's full chain, without Discord: gpg signs -> zero-width codec -> gpg re-verifies.
set -euo pipefail
cd "$(dirname "$0")"

export GNUPGHOME="${GNUPGHOME:-$PWD/test-gpghome}"
KEYID="${1:-$(gpg --with-colons --list-secret-keys "InvisiblePGP Test" 2>/dev/null | awk -F: '$1=="fpr"{print substr($10,length($10)-15); exit}')}"
[[ -n "$KEYID" ]] || { echo "No secret key in $GNUPGHOME" >&2; exit 1; }

MSG="${2:-Hello, this message is signed. Emoji: 🔐🗝️}"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

echo "keyring : $GNUPGHOME"
echo "key     : $KEYID"
echo

# The plugin's codec, transpiled from the TypeScript source -- not a parallel copy.
npx --yes esbuild ../src/plugins/invisiblePgp/zeroWidth.ts --format=esm --outfile=.zeroWidth.build.mjs --log-level=warning

printf '%s' "$MSG" > "$T/msg.txt"

echo "== 1. Detached signature (the exact arguments native.ts uses) =="
gpg --batch --no-tty --yes --detach-sign --digest-algo SHA512 \
    --local-user "$KEYID" --output "$T/sig.bin" < "$T/msg.txt"
echo "   ok"

echo "== 2. Zero-width encoding =="
node pgp-roundtrip.mjs encode "$T/msg.txt" "$T/sig.bin" "$KEYID" "$T/signed.txt"

echo "== 3. Decoding =="
node pgp-roundtrip.mjs decode "$T/signed.txt" "$T/visible.txt" "$T/sig2.bin"

cmp -s "$T/msg.txt" "$T/visible.txt" && echo "   visible text identical to the original" || { echo "   !! visible text altered" >&2; exit 1; }
cmp -s "$T/sig.bin" "$T/sig2.bin"    && echo "   signature identical byte for byte"  || { echo "   !! signature altered" >&2; exit 1; }

echo "== 4. gpg verification of the extracted signature =="
gpg --verify "$T/sig2.bin" "$T/visible.txt" 2>&1 | sed 's/^/   /'

echo "== 5. Negative control -- tampered message =="
sed 's/Bonjour/Bonsoir/' "$T/visible.txt" > "$T/tampered.txt"
if gpg --verify "$T/sig2.bin" "$T/tampered.txt" >/dev/null 2>&1; then
    echo "   !! an invalid signature was accepted" >&2; exit 1
else
    echo "   signature rejected on the modified message -- as expected"
fi

echo
echo "Full chain verified: gpg -> zero-width -> gpg."
