# Vencord InvisiblePGP — Synapse module
# SPDX-License-Identifier: GPL-3.0-or-later
"""Codec behaviour beyond the shared vectors.

The vectors prove the two implementations agree; these prove the Python side is right about the
cases the vectors only sample.
"""

from __future__ import annotations

import random

import pytest

from invisible_pgp.codec import (
    ALPHABETS, ANCHOR, BASE4, BASE16, BASE256, FRAME_V1, FRAME_V2, alphabet_by_name, build_frame,
    decode_bytes, decode_message, encode_bytes, encode_payload, has_payload, parse_frame,
)

SIG = bytes((i * 7 + 13) & 0xFF for i in range(119))
KEY_ID = "A1B2C3D4E5F60718"
TS = 1787314443


@pytest.mark.parametrize("alphabet", ALPHABETS, ids=lambda a: a.name)
class TestByteCodec:
    def test_round_trips_every_byte_value(self, alphabet) -> None:
        data = bytes(range(256))
        assert decode_bytes(encode_bytes(data, alphabet), alphabet) == data

    def test_uses_the_expected_number_of_codepoints(self, alphabet) -> None:
        assert len(encode_bytes(bytes(10), alphabet)) == 10 * (8 // alphabet.bits_per_symbol)

    def test_rejects_a_partial_byte(self, alphabet) -> None:
        if alphabet.bits_per_symbol == 8:
            pytest.skip("one symbol is already one byte")
        assert decode_bytes(encode_bytes(SIG, alphabet)[:-1], alphabet) is None

    def test_rejects_a_foreign_symbol(self, alphabet) -> None:
        other = next(a for a in ALPHABETS if a is not alphabet)
        assert decode_bytes(encode_bytes(SIG, alphabet) + other.symbols[0], alphabet) is None

    def test_rejects_an_empty_run(self, alphabet) -> None:
        assert decode_bytes("", alphabet) is None


class TestFrame:
    def test_round_trips_with_both_optional_fields(self) -> None:
        frame = parse_frame(build_frame(SIG, KEY_ID, TS))
        assert frame is not None
        assert (frame.version, frame.sig, frame.key_id, frame.timestamp) == (FRAME_V2, SIG, KEY_ID, TS)

    def test_omits_the_key_id_bytes_when_absent(self) -> None:
        assert len(build_frame(SIG)) == len(build_frame(SIG, KEY_ID)) - 8

    def test_uppercases_the_key_id(self) -> None:
        assert parse_frame(build_frame(SIG, KEY_ID.lower())).key_id == KEY_ID

    def test_ignores_a_malformed_key_id(self) -> None:
        assert parse_frame(build_frame(SIG, "not-hex-at-all")).key_id is None

    @pytest.mark.parametrize("sig,ts", [(b"", None), (bytes(0x10000), None), (SIG, 0x1_0000_0000)])
    def test_refuses_to_build_what_it_cannot_describe(self, sig, ts) -> None:
        with pytest.raises(ValueError):
            build_frame(sig, None, ts)

    def test_rejects_an_unknown_version(self) -> None:
        frame = bytearray(build_frame(SIG, KEY_ID, TS))
        frame[0] = 0x03
        assert parse_frame(bytes(frame)) is None

    def test_rejects_an_unknown_flag_bit(self) -> None:
        # Rejected rather than ignored so that each frame has exactly one byte representation.
        frame = bytearray(build_frame(SIG, KEY_ID, TS))
        frame[1] |= 0b100
        assert parse_frame(bytes(frame)) is None

    @pytest.mark.parametrize("cut", [1, 5, 12, 30])
    def test_rejects_a_truncated_frame(self, cut) -> None:
        assert parse_frame(build_frame(SIG, KEY_ID, TS)[:cut]) is None

    def test_rejects_unaccounted_trailing_bytes(self) -> None:
        assert parse_frame(build_frame(SIG, KEY_ID, TS) + b"\x00\x00\x00") is None


@pytest.mark.parametrize("alphabet", ALPHABETS, ids=lambda a: a.name)
class TestMessage:
    def test_recovers_text_and_signature(self, alphabet) -> None:
        text = "Hello, this message is signed. Emoji: 🔐🗝️"
        decoded = decode_message(text + encode_payload(SIG, alphabet, KEY_ID, TS))
        assert decoded.visible_text == text
        assert decoded.frame.sig == SIG
        assert decoded.alphabet is alphabet

    def test_identifies_the_alphabet_by_trial(self, alphabet) -> None:
        assert decode_message("x" + encode_payload(SIG, alphabet)).alphabet is alphabet

    def test_rejects_truncation(self, alphabet) -> None:
        message = "hi" + encode_payload(SIG, alphabet, KEY_ID, TS)
        assert decode_message(message[:-10]).frame is None

    def test_rejects_padding(self, alphabet) -> None:
        message = "hi" + encode_payload(SIG, alphabet, KEY_ID, TS)
        assert decode_message(message + alphabet.symbols[0]).frame is None


class TestConservativeDecoding:
    @pytest.mark.parametrize(
        "text", ["", "   ", "just a normal message", "no payload here 🔐", "I ❤️ you 👍🏽 🏳️‍🌈"]
    )
    def test_leaves_unsigned_text_untouched(self, text) -> None:
        decoded = decode_message(text)
        assert decoded.frame is None
        assert decoded.visible_text == text

    def test_does_not_eat_the_variation_selector_in_a_real_emoji(self) -> None:
        # ❤️ is U+2764 U+FE0F, and U+FE0F is also a base16/base256 symbol.
        assert not has_payload("I ❤️ you")
        assert decode_message("I ❤️ you").visible_text == "I ❤️ you"

    def test_keeps_a_trailing_emoji_when_the_message_is_signed(self) -> None:
        text = "ends in an emoji ❤️"
        decoded = decode_message(text + encode_payload(SIG, BASE16, KEY_ID, TS))
        assert decoded.visible_text == text
        assert decoded.frame.sig == SIG

    def test_ignores_stray_invisible_characters_mid_text(self) -> None:
        text = f"a{BASE4.symbols[0]}b{BASE4.symbols[1]}c"
        assert decode_message(text).frame is None
        assert decode_message(text).visible_text == text

    def test_rejects_a_run_mixing_alphabets(self) -> None:
        run = encode_bytes(build_frame(SIG, KEY_ID, TS), BASE16) + BASE256.symbols[200]
        assert decode_message("hi" + ANCHOR + run).frame is None

    def test_refuses_a_v1_frame_in_a_non_v1_alphabet(self) -> None:
        v1 = bytearray(12 + 4)
        v1[0] = FRAME_V1
        v1[1] = 0b01
        v1[10:12] = (4).to_bytes(2, "big")
        assert parse_frame(bytes(v1)) is not None
        assert decode_message(ANCHOR + encode_bytes(bytes(v1), BASE16)).frame is None
        assert decode_message(encode_bytes(bytes(v1), BASE4)).frame is not None

    def test_reads_a_legacy_base4_message_without_an_anchor(self) -> None:
        run = encode_bytes(build_frame(SIG, KEY_ID, TS), BASE4)
        assert decode_message("legacy" + run).frame.sig == SIG


class TestProperties:
    """The two properties the whole scheme rests on, over random input."""

    SEED = 20260821

    @pytest.mark.parametrize("alphabet", ALPHABETS, ids=lambda a: a.name)
    def test_encode_then_decode_is_the_identity(self, alphabet) -> None:
        rng = random.Random(self.SEED)
        for _ in range(200):
            sig = bytes(rng.randrange(256) for _ in range(rng.randint(1, 300)))
            key_id = f"{rng.randrange(16**16):016X}" if rng.random() < 0.5 else None
            ts = rng.randint(1, 0xFFFFFFFE) if rng.random() < 0.5 else None
            text = rng.choice(["", "plain", "I ❤️ you", "👨‍👩‍👧‍👦", "ends in ❤️"])

            decoded = decode_message(text + encode_payload(sig, alphabet, key_id, ts))
            assert decoded.frame is not None
            assert decoded.visible_text == text
            assert decoded.frame.sig == sig
            assert decoded.frame.key_id == key_id
            assert decoded.frame.timestamp == ts

    @pytest.mark.parametrize("alphabet", ALPHABETS, ids=lambda a: a.name)
    def test_a_mutated_payload_never_reproduces_the_original_frame(self, alphabet) -> None:
        rng = random.Random(self.SEED)
        original = build_frame(SIG, KEY_ID, TS)
        reference = parse_frame(original)
        symbols = list(encode_bytes(original, alphabet))

        for _ in range(200):
            at = rng.randrange(len(symbols))
            replacement = rng.choice(alphabet.symbols)
            if replacement == symbols[at]:
                continue

            mutated = list(symbols)
            mutated[at] = replacement
            frame = parse_frame(decode_bytes("".join(mutated), alphabet))
            assert frame is None or frame != reference

    def test_random_invisible_noise_is_never_a_signature(self) -> None:
        rng = random.Random(self.SEED)
        for _ in range(1000):
            alphabet = rng.choice(ALPHABETS)
            noise = "".join(rng.choice(alphabet.symbols) for _ in range(rng.randint(1, 200)))
            assert decode_message("noise" + ANCHOR + noise).frame is None


def test_alphabet_by_name_rejects_the_unknown() -> None:
    assert alphabet_by_name("base16") is BASE16
    with pytest.raises(ValueError):
        alphabet_by_name("base32")
