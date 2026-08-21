# Vencord InvisiblePGP — Synapse module
# SPDX-License-Identifier: GPL-3.0-or-later
"""Steganographic codec: arbitrary bytes <-> a run of invisible codepoints.

A direct port of ``src/plugins/invisiblePgp/codec.ts``. The two implementations are held to the
same behaviour by ``tests/vectors.json`` at the repository root; see ``SPEC.md`` for the format
itself. Keep the two files in step — a divergence here means a message signed in Discord stops
verifying on Matrix, which is exactly the failure this module exists to catch.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

#: Frame version. v1 is base4 plus the ``ipgp1`` canonical form; v2 is everything since.
FRAME_V1 = 0x01
FRAME_V2 = 0x02

_FLAG_HAS_KEY_ID = 1 << 0
#: Set when the signature covers the context binding rather than the bare text.
_FLAG_HAS_CONTEXT = 1 << 1
#: Every bit that means something. A frame setting any other bit is rejected.
_KNOWN_FLAGS = _FLAG_HAS_KEY_ID | _FLAG_HAS_CONTEXT

_KEY_ID_LEN = 8
_TIMESTAMP_LEN = 4
_SIG_LEN_LEN = 2

#: Separates the payload from the user's text.
#:
#: A variation selector modifies the character it follows, and U+FE0F in particular is the emoji
#: presentation selector. U+034F COMBINING GRAPHEME JOINER is defined to have no visible effect and
#: belongs to no alphabet here, so it gives the first selector a harmless base character.
ANCHOR = "͏"


@dataclass(frozen=True)
class Alphabet:
    """A set of invisible codepoints, where a symbol's index *is* its digit."""

    name: str
    bits_per_symbol: int
    symbols: Sequence[str]

    def __post_init__(self) -> None:
        assert len(self.symbols) == 2**self.bits_per_symbol


def _chars(start: int, count: int) -> tuple[str, ...]:
    return tuple(chr(start + i) for i in range(count))


#: ZWSP, ZWNJ, ZWJ, WORD JOINER.
BASE4 = Alphabet("base4", 2, ("​", "‌", "‍", "⁠"))
#: VS1-VS16. All BMP.
BASE16 = Alphabet("base16", 4, _chars(0xFE00, 16))
#: VS1-VS256. The first 16 are BMP; VS17-VS256 are astral.
BASE256 = Alphabet("base256", 8, _chars(0xFE00, 16) + _chars(0xE0100, 240))

ALPHABETS: tuple[Alphabet, ...] = (BASE4, BASE16, BASE256)

_BY_NAME = {a.name: a for a in ALPHABETS}

# base16 is a strict subset of base256, so a run cannot name its own alphabet. `decode_message`
# resolves it by trial decoding instead.
_DIGITS: dict[str, dict[str, int]] = {
    a.name: {sym: digit for digit, sym in enumerate(a.symbols)} for a in ALPHABETS
}
_ANY_SYMBOL: frozenset[str] = frozenset(sym for a in ALPHABETS for sym in a.symbols)


def alphabet_by_name(name: str) -> Alphabet:
    try:
        return _BY_NAME[name]
    except KeyError:
        raise ValueError(f"Unknown alphabet: {name}") from None


# ---------------------------------------------------------------------------------------------
# Bytes <-> symbols
# ---------------------------------------------------------------------------------------------


def encode_bytes(data: bytes, alphabet: Alphabet) -> str:
    """Encode bytes as a run of invisible codepoints, most significant bits first."""
    bits = alphabet.bits_per_symbol
    mask = (1 << bits) - 1
    symbols = alphabet.symbols

    out: list[str] = []
    for byte in data:
        for shift in range(8 - bits, -1, -bits):
            out.append(symbols[(byte >> shift) & mask])
    return "".join(out)


def decode_bytes(run: str, alphabet: Alphabet) -> bytes | None:
    """Inverse of :func:`encode_bytes`, or ``None`` if the run does not fit this alphabet."""
    bits = alphabet.bits_per_symbol
    per_byte = 8 // bits
    table = _DIGITS[alphabet.name]

    digits: list[int] = []
    for ch in run:
        digit = table.get(ch)
        if digit is None:
            return None
        digits.append(digit)

    if not digits or len(digits) % per_byte != 0:
        return None

    out = bytearray(len(digits) // per_byte)
    for i in range(len(out)):
        value = 0
        for d in range(per_byte):
            value = (value << bits) | digits[i * per_byte + d]
        out[i] = value
    return bytes(out)


# ---------------------------------------------------------------------------------------------
# Frame
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Frame:
    version: int
    sig: bytes
    key_id: str | None = None
    timestamp: int | None = None


def _header_length(version: int, flags: int) -> int:
    """v1 reserved the 8 key-id bytes unconditionally; v2 spends them only when the flag is set."""
    key_id_bytes = _KEY_ID_LEN if (version == FRAME_V1 or flags & _FLAG_HAS_KEY_ID) else 0
    timestamp_bytes = _TIMESTAMP_LEN if flags & _FLAG_HAS_CONTEXT else 0
    return 2 + key_id_bytes + timestamp_bytes + _SIG_LEN_LEN


def _is_key_id(value: str | None) -> bool:
    if value is None or len(value) != 16:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def build_frame(sig: bytes, key_id: str | None = None, timestamp: int | None = None) -> bytes:
    """Wrap a raw detached signature in a v2 frame."""
    if not sig:
        raise ValueError("Refusing to frame an empty signature")
    if len(sig) > 0xFFFF:
        raise ValueError("Signature is too large to frame (>65535 bytes)")

    has_key_id = _is_key_id(key_id)
    bound = timestamp is not None and timestamp > 0
    if bound and timestamp > 0xFFFFFFFF:  # type: ignore[operator]
        raise ValueError("Timestamp does not fit in 32 bits")

    flags = (_FLAG_HAS_KEY_ID if has_key_id else 0) | (_FLAG_HAS_CONTEXT if bound else 0)

    out = bytearray([FRAME_V2, flags])
    if has_key_id:
        out += bytes.fromhex(key_id)  # type: ignore[arg-type]
    if bound:
        out += int(timestamp).to_bytes(4, "big")  # type: ignore[arg-type]
    out += len(sig).to_bytes(2, "big")
    out += sig
    return bytes(out)


def parse_frame(frame: bytes) -> Frame | None:
    """Inverse of :func:`build_frame`; also reads legacy v1 frames. ``None`` for anything else."""
    if len(frame) < 2:
        return None

    version = frame[0]
    if version not in (FRAME_V1, FRAME_V2):
        return None

    flags = frame[1]
    # Unused bits are rejected rather than ignored, so each frame has exactly one byte
    # representation and a relay cannot reword one without changing what it decodes to.
    if flags & ~_KNOWN_FLAGS:
        return None

    if len(frame) < _header_length(version, flags):
        return None

    offset = 2
    key_id: str | None = None
    if version == FRAME_V1 or flags & _FLAG_HAS_KEY_ID:
        if flags & _FLAG_HAS_KEY_ID:
            key_id = frame[offset : offset + _KEY_ID_LEN].hex().upper()
        offset += _KEY_ID_LEN

    timestamp: int | None = None
    if flags & _FLAG_HAS_CONTEXT:
        timestamp = int.from_bytes(frame[offset : offset + _TIMESTAMP_LEN], "big")
        offset += _TIMESTAMP_LEN

    sig_len = int.from_bytes(frame[offset : offset + _SIG_LEN_LEN], "big")
    offset += _SIG_LEN_LEN

    # Rejecting a length that does not account for every remaining byte is what stops a run padded
    # with stray invisible characters from being read as a shorter, valid signature.
    if sig_len == 0 or offset + sig_len != len(frame):
        return None

    return Frame(version=version, sig=frame[offset:], key_id=key_id, timestamp=timestamp)


# ---------------------------------------------------------------------------------------------
# Message <-> payload
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class DecodedMessage:
    #: The message with the payload run removed, or the input untouched when there is no payload.
    visible_text: str
    frame: Frame | None
    alphabet: Alphabet | None = None


def _find_trailing_run(text: str) -> tuple[str, str]:
    """Split ``text`` into (visible, run).

    Deliberately *not* a global strip. U+FE0F is the emoji presentation selector, so removing every
    alphabet character wherever it appears would quietly rewrite any emoji the user actually typed
    (``❤️`` is U+2764 U+FE0F). Only a contiguous run at the very end can be ours.
    """
    start = len(text)
    while start > 0 and text[start - 1] in _ANY_SYMBOL:
        start -= 1

    visible_end = start
    if visible_end > 0 and text[visible_end - 1] == ANCHOR:
        visible_end -= 1

    return text[:visible_end], text[start:]


def decode_message(text: str) -> DecodedMessage:
    """Split a message into its visible text and the signature hidden at the end of it.

    When there is no valid payload the text is returned untouched — a message is never altered on
    the strength of a guess.
    """
    unsigned = DecodedMessage(visible_text=text, frame=None)

    visible, run = _find_trailing_run(text)
    if not run:
        return unsigned

    # Try every alphabet. A run only decodes to a valid frame under the alphabet that wrote it: any
    # other reading has to land on a known version byte *and* a length field that accounts for
    # exactly the remaining bytes, which is not something a misreading does by accident.
    candidates: list[DecodedMessage] = []
    for alphabet in ALPHABETS:
        data = decode_bytes(run, alphabet)
        if data is None:
            continue

        frame = parse_frame(data)
        if frame is None:
            continue

        # A v1 frame is base4 by definition; anything else is a forgery or a bug.
        if frame.version == FRAME_V1 and alphabet is not BASE4:
            continue

        candidates.append(DecodedMessage(visible_text=visible, frame=frame, alphabet=alphabet))

    # Two readings of the same run is not a verdict we can defend, so it is not one we return.
    if len(candidates) != 1:
        return unsigned

    return candidates[0]


def encode_payload(
    sig: bytes,
    alphabet: Alphabet,
    key_id: str | None = None,
    timestamp: int | None = None,
) -> str:
    """Build the invisible run to append to a message."""
    return ANCHOR + encode_bytes(build_frame(sig, key_id, timestamp), alphabet)


def has_payload(text: str) -> bool:
    """True if the text ends in a run that parses as one of our frames."""
    return decode_message(text).frame is not None
