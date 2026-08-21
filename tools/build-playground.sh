#!/usr/bin/env bash
# Rebuilds tools/codec-playground.html from its sources.
#
# The page inlines openpgp.js (~380 KB minified) because it has to work opened straight from disk,
# with no server and no CDN. The result is therefore a build artifact: edit page-body.html and
# page-logic.js, never codec-playground.html.
set -euo pipefail
cd "$(dirname "$0")"

# Dependencies live at the repository root — openpgp is already a devDependency there, and a
# second package.json in tools/ was only ever a way for the two to drift apart.
[[ -d ../node_modules ]] || (cd .. && npm install)

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
printf 'import * as openpgp from "openpgp";\nglobalThis.openpgp = openpgp;\n' > .openpgp-entry.mjs

# The plugin's own codec, not a copy of it: a demo that quietly disagrees with the plugin is worse
# than no demo. page-logic.js reads it off globalThis.ipgp.
cat > .ipgp-entry.mjs <<'ENTRY'
import * as codec from "../src/plugins/invisiblePgp/codec.ts";
import * as binding from "../src/plugins/invisiblePgp/binding.ts";
globalThis.ipgp = { ...codec, ...binding };
ENTRY

trap 'rm -rf "$TMP" .openpgp-entry.mjs .ipgp-entry.mjs' EXIT

npx --yes esbuild .openpgp-entry.mjs --bundle --format=iife --minify \
    --outfile="$TMP/openpgp.bundle.js" --log-level=warning

npx --yes esbuild .ipgp-entry.mjs --bundle --format=iife \
    --outfile="$TMP/ipgp.bundle.js" --log-level=warning

python3 - "$TMP/openpgp.bundle.js" "$TMP/ipgp.bundle.js" <<'PY'
import sys
openpgp_bundle = open(sys.argv[1], encoding="utf-8").read()
ipgp_bundle = open(sys.argv[2], encoding="utf-8").read()
body = open("page-body.html", encoding="utf-8").read().rstrip()
logic = open("page-logic.js", encoding="utf-8").read()
open("codec-playground.html", "w", encoding="utf-8").write(
    body
    + "\n\n<script>" + openpgp_bundle + "</script>"
    + "\n\n<script>" + ipgp_bundle + "</script>"
    + "\n\n<script>\n" + logic + "</script>\n")
print("codec-playground.html rebuilt")
PY
