# Vencord InvisiblePGP — Synapse module
# SPDX-License-Identifier: GPL-3.0-or-later
"""Context binding — the exact string that gets signed.

A direct port of ``src/plugins/invisiblePgp/binding.ts``; see ``SPEC.md``. Signing the message text
alone authenticates *what* was said but not *where*, *when* or *by whom*, so a genuine message
could be lifted into another room and still verify. Binding the room, the sender and a timestamp
into the signed data closes that.
"""

from __future__ import annotations

from dataclasses import dataclass

from .codec import FRAME_V1, FRAME_V2

#: Platforms that can produce a binding. The tag is part of the signed data, so a Discord
#: signature cannot be replayed as a Matrix one.
PLATFORMS = ("discord", "matrix")


@dataclass(frozen=True)
class MessageContext:
    platform: str
    #: Channel id on Discord, room id on Matrix.
    conversation_id: str
    #: User id on Discord, MXID on Matrix.
    author_id: str
    #: Unix seconds, chosen by the sender's clock.
    timestamp: int
    #: Reference to the media this message carries, or "" when it carries none.
    #:
    #: Without this, a signature over an image message covers only its filename, so a captured
    #: signed message could keep its signature while pointing at a different file. On Matrix this
    #: is the ``mxc://`` URI (or the encrypted ``file.url``); Discord signs the empty string.
    attachment: str = ""


_V1_TAG = "ipgp1"
_V2_TAG = "ipgp2"


def _field(value: str) -> str:
    # UTF-8 byte count, not codepoint count, so implementations in different languages agree.
    return f"{len(value.encode('utf-8'))}:{value}\n"


def canonical_signed_text(
    ctx: MessageContext, visible_text: str, frame_version: int = FRAME_V2
) -> str:
    """Build the exact string that gets signed, in the form matching the given frame version.

    v1 was ``ipgp1\\n<channel>\\n<author>\\n<ts>\\n<text>``, safe only because Discord ids were
    validated as digits so nothing could contain the delimiter. Matrix ids look like
    ``!room:server``, so v2 length-prefixes every field instead and is unambiguous for any content.
    The free-form text stays last and unprefixed, where it cannot shift a boundary.
    """
    if frame_version == FRAME_V1:
        # Reproduced verbatim so pre-v2 signatures keep verifying. Never emitted anymore.
        return "\n".join(
            [_V1_TAG, ctx.conversation_id, ctx.author_id, str(ctx.timestamp), visible_text]
        )
    if frame_version != FRAME_V2:
        raise ValueError(f"Unknown frame version: {frame_version}")

    return (
        _V2_TAG
        + "\n"
        + _field(ctx.platform)
        + _field(ctx.conversation_id)
        + _field(ctx.author_id)
        + _field(str(ctx.timestamp))
        + _field(ctx.attachment)
        + visible_text
    )


def is_usable_context(ctx: MessageContext) -> bool:
    """A context is usable when every bound field is present and non-empty.

    v2 needs no character restrictions, but an empty id would bind the message to nothing in
    particular, so it is rejected rather than signed over.
    """
    return (
        ctx.platform in PLATFORMS
        and isinstance(ctx.conversation_id, str)
        and len(ctx.conversation_id) > 0
        and isinstance(ctx.author_id, str)
        and len(ctx.author_id) > 0
        and isinstance(ctx.timestamp, int)
        and not isinstance(ctx.timestamp, bool)
        and ctx.timestamp > 0
    )
