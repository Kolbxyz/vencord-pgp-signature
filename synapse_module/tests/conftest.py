# Vencord InvisiblePGP — Synapse module
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared fixtures.

The gpg fixtures build a throwaway keyring in a temp directory and sign with a real key. Stubbing
gpg out would let a signature that does not actually verify pass the suite, which is precisely the
bug the module exists to catch.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

GPG = shutil.which("gpg")
requires_gpg = pytest.mark.skipif(GPG is None, reason="gpg is not installed")


@dataclass
class SigningKey:
    home: str
    fingerprint: str

    def sign(self, text: str) -> bytes:
        proc = subprocess.run(
            [GPG, "--homedir", self.home, "--batch", "--no-tty", "--yes",
             "--detach-sign", "--digest-algo", "SHA512",
             "--local-user", self.fingerprint, "--output", "-"],
            input=text.encode("utf-8"), capture_output=True, check=True,
        )
        return proc.stdout


def _generate(home: Path, name: str) -> str:
    home.mkdir(parents=True, exist_ok=True)
    home.chmod(0o700)
    subprocess.run(
        [GPG, "--homedir", str(home), "--batch", "--no-tty", "--yes",
         "--quick-generate-key", f"{name} <{name}@example.org>", "ed25519", "sign", "never"],
        capture_output=True, check=True,
    )
    listing = subprocess.run(
        [GPG, "--homedir", str(home), "--batch", "--with-colons", "--list-secret-keys"],
        capture_output=True, check=True, text=True,
    ).stdout
    for line in listing.splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9].upper()
    raise AssertionError("no fingerprint in gpg output")


@pytest.fixture(scope="session")
def signer(tmp_path_factory: pytest.TempPathFactory) -> SigningKey:
    """A key that the module's keyring trusts."""
    if GPG is None:
        pytest.skip("gpg is not installed")
    home = tmp_path_factory.mktemp("gnupg-signer")
    return SigningKey(home=str(home), fingerprint=_generate(home, "alice"))


@pytest.fixture(scope="session")
def impostor(tmp_path_factory: pytest.TempPathFactory) -> SigningKey:
    """A different, valid key — the "someone else signed it" case."""
    if GPG is None:
        pytest.skip("gpg is not installed")
    home = tmp_path_factory.mktemp("gnupg-impostor")
    return SigningKey(home=str(home), fingerprint=_generate(home, "mallory"))


@pytest.fixture(scope="session")
def keyring(tmp_path_factory: pytest.TempPathFactory, signer: SigningKey, impostor: SigningKey) -> str:
    """A verification keyring holding both public keys.

    Both on purpose: it is what proves the module checks *which* key signed, rather than merely
    that some trusted key did.
    """
    home = tmp_path_factory.mktemp("gnupg-verify")
    home.chmod(0o700)
    for key in (signer, impostor):
        exported = subprocess.run(
            [GPG, "--homedir", key.home, "--batch", "--armor", "--export", key.fingerprint],
            capture_output=True, check=True,
        ).stdout
        subprocess.run(
            [GPG, "--homedir", str(home), "--batch", "--no-tty", "--import"],
            input=exported, capture_output=True, check=True,
        )
    return str(home)
