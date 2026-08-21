#!/usr/bin/env bash
# Replays, from WSL, the exact command native.ts sends to gpg -- but with the Windows gpg, the
# only one that can see the YubiKey. It is also the one Vencord Desktop will use.
set -uo pipefail

find_gpg() {
    for p in \
        "/mnt/c/Program Files (x86)/GnuPG/bin/gpg.exe" \
        "/mnt/c/Program Files/GnuPG/bin/gpg.exe" \
        "/mnt/c/Program Files (x86)/Gpg4win/bin/gpg.exe"; do
        [[ -x "$p" ]] && { printf '%s' "$p"; return 0; }
    done
    command -v gpg.exe 2>/dev/null && return 0
    return 1
}

GPG="$(find_gpg)" || {
    echo "gpg.exe not found. Install Gpg4win:  winget install --id GnuPG.Gpg4win -e" >&2
    exit 1
}
echo "gpg      : $GPG"
echo "version  : $("$GPG" --version | head -1)"
echo

echo "== 1. Card status =="
if ! "$GPG" --card-status; then
    echo "!! The card is not being read. Check that Kleopatra/Firefox is not holding it," >&2
    echo "   and that CCID mode is enabled (ykman config usb --enable CCID)." >&2
    exit 1
fi
echo

echo "== 2. Available secret keys (what the plugin key picker will show) =="
"$GPG" --with-colons --list-secret-keys | awk -F: '
    $1=="sec" { algo=$4; card=($15!="" ? "  [on card]" : "") }
    $1=="fpr" && !fpr { fpr=$10 }
    $1=="uid" && fpr  { printf "  %s  %s%s\n", substr(fpr,length(fpr)-15), $10, card; fpr="" }'
echo

KEYID="${1:-}"
if [[ -z "$KEYID" ]]; then
    echo "Usage: $0 <KEYID>    (16 hex, left column above)"
    echo "No KEYID given -- stopping before the signing test."
    exit 0
fi

MSG="Hello, this message is signed."
SIG="$(mktemp)"; DATA="$(mktemp)"
trap 'rm -f "$SIG" "$DATA"' EXIT
printf '%s' "$MSG" > "$DATA"

echo "== 3. Detached signature -- TOUCH THE YUBIKEY IF IT BLINKS =="
echo "   (same arguments as native.ts)"
if ! printf '%s' "$MSG" | "$GPG" \
        --batch --no-tty --yes \
        --detach-sign --digest-algo SHA512 \
        --local-user "$KEYID" \
        --output - > "$SIG"; then
    echo "!! Signing failed." >&2
    exit 1
fi

BYTES=$(wc -c < "$SIG")
echo "   signature: $BYTES bytes  ->  $(( (BYTES + 16) * 4 )) invisible characters in the message"
echo

echo "== 4. Verification =="
"$GPG" --verify "$(wslpath -w "$SIG")" "$(wslpath -w "$DATA")" || { echo "!! Verification failed." >&2; exit 1; }
echo

echo "== 5. Signature in hex =="
xxd -p "$SIG" | tr -d '\n'; echo
echo
echo "Path to put in the plugin settings (gpgPath):"
echo "  $(wslpath -w "$GPG")"
