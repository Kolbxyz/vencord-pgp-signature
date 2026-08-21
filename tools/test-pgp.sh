#!/usr/bin/env bash
# The plugin's full chain, without Discord:
#   gpg signs the canonical string -> codec -> codec -> gpg re-verifies.
#
# Runs once per alphabet, because the codec is the part that changed and the point of the script is
# that all three round-trip through a real signature identically.
set -euo pipefail
cd "$(dirname "$0")"

export GNUPGHOME="${GNUPGHOME:-$PWD/test-gpghome}"
mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"

# `|| true` is load-bearing: gpg exits 2 when the keyring is empty, and under `set -euo pipefail`
# that would kill the script here rather than letting it generate the key it is about to need.
find_key() {
    gpg --batch --with-colons --list-secret-keys 2>/dev/null \
        | awk -F: '$1=="fpr"{print substr($10,length($10)-15); exit}' \
        || true
}

KEYID="${1:-$(find_key)}"

if [[ -z "$KEYID" ]]; then
    echo "No secret key in $GNUPGHOME — generating a throwaway one."

    # --pinentry-mode loopback with an empty --passphrase is what makes this work with no
    # controlling terminal: otherwise gpg-agent reaches for a pinentry program and dies with
    # "Inappropriate ioctl for device". It also matters later — a key created *without* it holds an
    # agent-managed passphrase, so even signing needs a pinentry and fails on a headless machine.
    gpg --batch --no-tty --yes \
        --pinentry-mode loopback --passphrase '' \
        --quick-generate-key "InvisiblePGP Test <test@example.org>" ed25519 sign never

    KEYID="$(find_key)"
    [[ -n "$KEYID" ]] || { echo "gpg could not generate a test key" >&2; exit 1; }
fi

MSG="${2:-Hello, this message is signed. Emoji: 🔐🗝️ and a heart ❤️}"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

echo "keyring : $GNUPGHOME"
echo "key     : $KEYID"
echo

# The plugin's own modules, transpiled from source — not a parallel copy.
mkdir -p .build
# --bundle, not plain transpile: the sources import each other without file extensions, which
# node's ESM resolver will not follow.
npx --yes esbuild ../src/plugins/invisiblePgp/codec.ts ../src/plugins/invisiblePgp/binding.ts \
    --bundle --format=esm --outdir=.build --out-extension:.js=.mjs --log-level=warning

printf '%s' "$MSG" > "$T/msg.txt"

for ALPHABET in base4 base16 base256; do
    echo "== $ALPHABET =="

    echo " 1. canonical signed string"
    node pgp-roundtrip.mjs canonical "$T/msg.txt" "$T/canonical.txt"

    echo " 2. detached signature (the exact arguments native.ts uses)"
    gpg --batch --no-tty --yes --detach-sign --digest-algo SHA512 \
        --local-user "$KEYID" --output "$T/sig.bin" < "$T/canonical.txt"
    echo "   ok"

    echo " 3. encoding"
    node pgp-roundtrip.mjs encode "$T/msg.txt" "$T/sig.bin" "$KEYID" "$ALPHABET" "$T/signed.txt"

    echo " 4. decoding"
    node pgp-roundtrip.mjs decode "$T/signed.txt" "$T/visible.txt" "$T/sig2.bin"

    cmp -s "$T/msg.txt" "$T/visible.txt" || { echo "   !! visible text altered" >&2; exit 1; }
    cmp -s "$T/sig.bin" "$T/sig2.bin"    || { echo "   !! signature altered" >&2; exit 1; }
    echo "   visible text and signature both identical"

    echo " 5. gpg verification, against the rebuilt canonical string"
    node pgp-roundtrip.mjs canonical "$T/visible.txt" "$T/canonical2.txt"
    gpg --verify "$T/sig2.bin" "$T/canonical2.txt" 2>&1 | sed 's/^/   /'

    echo " 6. negative control: one flipped byte in the signed data"
    # Flip the final byte rather than substituting words: a text-substitution control silently
    # stops testing anything the moment the sample message changes.
    head -c -1 "$T/canonical2.txt" > "$T/tampered.txt"
    printf 'X' >> "$T/tampered.txt"
    cmp -s "$T/canonical2.txt" "$T/tampered.txt" && { echo "   !! control did not modify anything" >&2; exit 1; }

    if gpg --verify "$T/sig2.bin" "$T/tampered.txt" >/dev/null 2>&1; then
        echo "   !! an invalid signature was accepted" >&2; exit 1
    fi
    echo "   tampered data rejected — as expected"

    echo " 7. negative control: a different channel"
    IPGP_TIMESTAMP=1787314443 node pgp-roundtrip.mjs canonical "$T/visible.txt" "$T/canonical3.txt"
    sed -i 's/1234567890123456789/1111111111111111111/' "$T/canonical3.txt"
    if gpg --verify "$T/sig2.bin" "$T/canonical3.txt" >/dev/null 2>&1; then
        echo "   !! a message lifted into another channel was accepted" >&2; exit 1
    fi
    echo "   relocated message rejected — context binding works"
    echo
done

echo "Full chain verified for all three alphabets: gpg -> codec -> codec -> gpg."
