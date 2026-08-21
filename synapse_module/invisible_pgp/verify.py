# Vencord InvisiblePGP — Synapse module
# SPDX-License-Identifier: GPL-3.0-or-later
"""Detached OpenPGP signature verification, by driving ``gpg`` directly.

Deliberately not a library binding. This code runs inside a homeserver process, so every extra
dependency is one more thing that can pull in a CVE; and shelling out to the same ``gpg`` the
Vencord plugin signs with keeps the two halves on identical crypto.

Verdicts are read from ``--status-fd``, never from the human-readable output, which is localised
and not a stable interface.
"""

from __future__ import annotations

import enum
import logging
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

#: gpg is fast, but a wedged agent must not stall event persistence.
DEFAULT_TIMEOUT_SEC = 10


class Verdict(enum.Enum):
    """Why a signature was or was not accepted. Every non-VALID value blocks the message."""

    VALID = "valid"
    #: A well-formed signature that does not match the data.
    BAD_SIGNATURE = "bad_signature"
    #: Valid, but made by a key other than the one configured for this sender.
    WRONG_KEY = "wrong_key"
    #: The signing key is expired or revoked. Cryptographically fine, not trustworthy.
    KEY_UNUSABLE = "key_unusable"
    #: The key is not in the module's keyring at all.
    UNKNOWN_KEY = "unknown_key"
    #: gpg was missing, timed out, or failed in a way we could not classify.
    ERROR = "error"


@dataclass(frozen=True)
class VerifyResult:
    verdict: Verdict
    #: Full uppercase fingerprint of the signing key, when gpg reported one.
    fingerprint: str | None = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.verdict is Verdict.VALID


class SignatureVerifier:
    """Verifies detached signatures against a keyring the module owns.

    The keyring is deliberately separate from any system keyring: it should contain exactly the
    public keys of the identities being enforced, so that a key trusted for some unrelated purpose
    can never satisfy a check here.
    """

    def __init__(
        self,
        gnupg_home: str,
        gpg_binary: str = "gpg",
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    ) -> None:
        self._home = gnupg_home
        self._binary = gpg_binary
        self._timeout = timeout_sec

    def verify(self, signature: bytes, signed_text: str, expected_fingerprint: str) -> VerifyResult:
        """Check ``signature`` over ``signed_text``, requiring ``expected_fingerprint``.

        The fingerprint check is not decoration. Without it any key in the keyring would satisfy
        any sender, so adding a second identity would silently let each impersonate the other.
        """
        expected = expected_fingerprint.replace(" ", "").upper()

        try:
            status = self._run_gpg(signature, signed_text.encode("utf-8"))
        except FileNotFoundError:
            return VerifyResult(Verdict.ERROR, detail=f"gpg binary not found: {self._binary}")
        except subprocess.TimeoutExpired:
            return VerifyResult(Verdict.ERROR, detail="gpg timed out")
        except OSError as exc:  # pragma: no cover - environment specific
            return VerifyResult(Verdict.ERROR, detail=f"could not run gpg: {exc}")

        return self._interpret(status, expected)

    def _run_gpg(self, signature: bytes, data: bytes) -> list[str]:
        # gpg needs the detached signature as a file; the signed data goes in on stdin.
        with tempfile.NamedTemporaryFile(suffix=".sig") as sig_file:
            sig_file.write(signature)
            sig_file.flush()

            proc = subprocess.run(
                [
                    self._binary,
                    "--homedir", self._home,
                    "--batch",
                    "--no-tty",
                    # Never reach for a keyserver or a local trust decision: the only question is
                    # whether this exact key made this signature.
                    "--no-auto-key-retrieve",
                    "--no-default-keyring",
                    "--keyring", str(Path(self._home) / "pubring.kbx"),
                    "--status-fd", "1",
                    "--verify", sig_file.name, "-",
                ],
                input=data,
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )

        return proc.stdout.decode("utf-8", "replace").splitlines()

    @staticmethod
    def _interpret(status_lines: list[str], expected: str) -> VerifyResult:
        codes: set[str] = set()
        fingerprint: str | None = None

        for line in status_lines:
            if not line.startswith("[GNUPG:] "):
                continue
            parts = line[len("[GNUPG:] ") :].split()
            if not parts:
                continue
            codes.add(parts[0])
            if parts[0] == "VALIDSIG" and len(parts) > 1:
                fingerprint = parts[1].upper()

        # Order matters: an expired or revoked key still emits VALIDSIG, so it has to be caught
        # before the success case rather than after it.
        if "NO_PUBKEY" in codes:
            return VerifyResult(Verdict.UNKNOWN_KEY, fingerprint, "signing key not in the keyring")
        if "BADSIG" in codes:
            return VerifyResult(Verdict.BAD_SIGNATURE, fingerprint, "signature does not match the data")
        if codes & {"EXPKEYSIG", "REVKEYSIG"}:
            return VerifyResult(Verdict.KEY_UNUSABLE, fingerprint, "signing key is expired or revoked")
        if "EXPSIG" in codes:
            return VerifyResult(Verdict.KEY_UNUSABLE, fingerprint, "signature itself has expired")
        if "ERRSIG" in codes:
            return VerifyResult(Verdict.ERROR, fingerprint, "gpg could not check the signature")

        if "GOODSIG" not in codes or fingerprint is None:
            return VerifyResult(Verdict.ERROR, fingerprint, "gpg reported no usable verdict")

        if fingerprint != expected:
            return VerifyResult(
                Verdict.WRONG_KEY,
                fingerprint,
                f"signed by {fingerprint}, expected {expected}",
            )

        return VerifyResult(Verdict.VALID, fingerprint)
