# Vencord InvisiblePGP — Synapse module
# SPDX-License-Identifier: GPL-3.0-or-later
"""Signature verification against a real gpg.

The status-fd parsing is tested directly as well as end to end: it is the part that decides whether
a message is trusted, and gpg's ordering rules there are easy to get subtly wrong — an expired key
still emits ``VALIDSIG``, so a naive reading accepts it.
"""

from __future__ import annotations

import pytest

from invisible_pgp.verify import SignatureVerifier, Verdict

from conftest import requires_gpg

FP = "0123456789ABCDEF0123456789ABCDEF01234567"
OTHER = "FEDCBA9876543210FEDCBA9876543210FEDCBA98"

interpret = SignatureVerifier._interpret


def status(*codes: str) -> list[str]:
    return [f"[GNUPG:] {code}" for code in codes]


class TestStatusInterpretation:
    def test_a_good_signature_from_the_expected_key_is_valid(self) -> None:
        result = interpret(status("GOODSIG X alice", f"VALIDSIG {FP} 2026-01-01"), FP)
        assert result.verdict is Verdict.VALID
        assert result.fingerprint == FP
        assert result.ok

    def test_a_good_signature_from_another_key_is_not_accepted(self) -> None:
        # Without this check, adding a second identity would let each impersonate the other.
        result = interpret(status("GOODSIG X mallory", f"VALIDSIG {OTHER} 2026-01-01"), FP)
        assert result.verdict is Verdict.WRONG_KEY
        assert not result.ok

    def test_a_bad_signature_is_rejected(self) -> None:
        assert interpret(status("BADSIG X alice"), FP).verdict is Verdict.BAD_SIGNATURE

    def test_an_unknown_key_is_reported_as_such(self) -> None:
        assert interpret(status("NO_PUBKEY ABC"), FP).verdict is Verdict.UNKNOWN_KEY

    @pytest.mark.parametrize("code", ["EXPKEYSIG", "REVKEYSIG"])
    def test_an_expired_or_revoked_key_is_refused_despite_validsig(self, code) -> None:
        # These emit VALIDSIG too. Checking for GOODSIG first would accept a revoked key.
        result = interpret(status(f"{code} X alice", "GOODSIG X alice", f"VALIDSIG {FP} x"), FP)
        assert result.verdict is Verdict.KEY_UNUSABLE

    def test_an_expired_signature_is_refused(self) -> None:
        assert interpret(status("EXPSIG X", "GOODSIG X", f"VALIDSIG {FP} x"), FP).verdict \
            is Verdict.KEY_UNUSABLE

    def test_an_uncheckable_signature_is_an_error(self) -> None:
        assert interpret(status("ERRSIG A B C"), FP).verdict is Verdict.ERROR

    @pytest.mark.parametrize("lines", [[], ["not a status line"], status("GOODSIG X")])
    def test_silence_is_never_success(self, lines) -> None:
        # No VALIDSIG means no fingerprint, so there is nothing to have checked.
        assert interpret(lines, FP).verdict is Verdict.ERROR

    def test_compares_fingerprints_case_insensitively(self) -> None:
        assert interpret(status("GOODSIG X", f"VALIDSIG {FP.lower()} x"), FP).verdict is Verdict.VALID


@requires_gpg
class TestAgainstRealGpg:
    def test_accepts_a_genuine_signature(self, keyring, signer) -> None:
        verifier = SignatureVerifier(gnupg_home=keyring)
        assert verifier.verify(signer.sign("hello"), "hello", signer.fingerprint).ok

    def test_rejects_a_signature_over_different_text(self, keyring, signer) -> None:
        verifier = SignatureVerifier(gnupg_home=keyring)
        result = verifier.verify(signer.sign("hello"), "hello!", signer.fingerprint)
        assert result.verdict is Verdict.BAD_SIGNATURE

    def test_rejects_a_genuine_signature_by_the_wrong_key(self, keyring, signer, impostor) -> None:
        # Both keys are in the keyring, so only the fingerprint check can catch this.
        verifier = SignatureVerifier(gnupg_home=keyring)
        result = verifier.verify(impostor.sign("hello"), "hello", signer.fingerprint)
        assert result.verdict is Verdict.WRONG_KEY

    def test_rejects_garbage_in_place_of_a_signature(self, keyring, signer) -> None:
        verifier = SignatureVerifier(gnupg_home=keyring)
        assert not verifier.verify(b"\x00" * 64, "hello", signer.fingerprint).ok

    def test_round_trips_text_full_of_awkward_unicode(self, keyring, signer) -> None:
        verifier = SignatureVerifier(gnupg_home=keyring)
        for text in ["I ❤️ you", "👨‍👩‍👧‍👦", "line\nbreak", "  padded  ", "", "naïve façade"]:
            assert verifier.verify(signer.sign(text), text, signer.fingerprint).ok, repr(text)

    def test_a_missing_binary_is_an_error_not_a_pass(self, keyring, signer) -> None:
        verifier = SignatureVerifier(gnupg_home=keyring, gpg_binary="/nonexistent/gpg")
        result = verifier.verify(signer.sign("hello"), "hello", signer.fingerprint)
        assert result.verdict is Verdict.ERROR
        assert not result.ok
