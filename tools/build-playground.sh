#!/usr/bin/env bash
# Rebuilds tools/codec-playground.html from its sources.
#
# The page inlines openpgp.js (~380 KB minified) because it has to work opened straight from disk,
# with no server and no CDN. The result is therefore a build artifact: edit page-body.html and
# page-logic.js, never codec-playground.html.
set -euo pipefail
cd "$(dirname "$0")"

[[ -d node_modules ]] || npm install

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
printf 'import * as openpgp from "openpgp";\nglobalThis.openpgp = openpgp;\n' > .openpgp-entry.mjs
trap 'rm -rf "$TMP" .openpgp-entry.mjs' EXIT

npx --yes esbuild .openpgp-entry.mjs --bundle --format=iife --minify \
    --outfile="$TMP/openpgp.bundle.js" --log-level=warning

python3 - "$TMP/openpgp.bundle.js" <<'PY'
import sys
bundle = open(sys.argv[1], encoding="utf-8").read()
body = open("page-body.html", encoding="utf-8").read().rstrip()
logic = open("page-logic.js", encoding="utf-8").read()
open("codec-playground.html", "w", encoding="utf-8").write(
    body + "\n\n<script>" + bundle + "</script>\n\n<script>\n" + logic + "</script>\n")
print("codec-playground.html rebuilt")
PY
