# Vencord InvisiblePGP — Synapse module
# SPDX-License-Identifier: GPL-3.0-or-later
"""The Python half of the cross-language contract.

``src/plugins/invisiblePgp/__tests__/vectors.test.ts`` runs the same file through the TypeScript
implementation. If one side drifts, exactly one of the two suites goes red — which is the whole
reason the vectors are a committed artefact rather than something each side generates for itself.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from invisible_pgp.binding import MessageContext, canonical_signed_text
from invisible_pgp.codec import decode_message

VECTORS = json.loads((Path(__file__).resolve().parents[2] / "tests" / "vectors.json").read_text("utf-8"))


def _ident(vector: dict) -> str:
    return vector["name"]


def test_vectors_file_is_the_expected_shape() -> None:
    assert VECTORS["version"] == 2
    assert {v["alphabet"] for v in VECTORS["codec"]} >= {"base4", "base16", "base256"}
    assert any(v["expect"] is None for v in VECTORS["codec"]), "negative cases must be present"
    assert any("legacy-v1" in v["name"] for v in VECTORS["codec"])


@pytest.mark.parametrize("vector", VECTORS["codec"], ids=_ident)
def test_codec_vector(vector: dict) -> None:
    decoded = decode_message(vector["message"])

    if vector["expect"] is None:
        assert decoded.frame is None, vector["why"]
        # A rejected payload must leave the message exactly as it arrived.
        assert decoded.visible_text == vector["message"]
        return

    expected = vector["expect"]
    assert decoded.frame is not None, vector["why"]
    assert decoded.visible_text == expected["visibleText"]
    assert decoded.frame.sig.hex() == expected["sigHex"]
    assert decoded.frame.key_id == expected["keyId"]
    assert decoded.frame.timestamp == expected["timestamp"]
    assert decoded.alphabet is not None and decoded.alphabet.name == vector["alphabet"]


@pytest.mark.parametrize("vector", VECTORS["binding"], ids=_ident)
def test_binding_vector(vector: dict) -> None:
    ctx = MessageContext(
        platform=vector["context"]["platform"],
        conversation_id=vector["context"]["conversationId"],
        author_id=vector["context"]["authorId"],
        timestamp=vector["context"]["timestamp"],
    )
    assert canonical_signed_text(ctx, vector["visibleText"], vector["frameVersion"]) == vector["canonical"]
