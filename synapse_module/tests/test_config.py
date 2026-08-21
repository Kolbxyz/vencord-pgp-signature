# Vencord InvisiblePGP — Synapse module
# SPDX-License-Identifier: GPL-3.0-or-later
"""Configuration validation.

Every case here is a mistake someone will actually make in ``homeserver.yaml``. Each must fail at
startup with a message that says what to fix, rather than at 3am under traffic.
"""

from __future__ import annotations

import pytest

from invisible_pgp.config import POLICY_NOTIFY_ONLY, POLICY_STRIP, ConfigError, parse_config

FP = "0123456789ABCDEF0123456789ABCDEF01234567"
MINIMAL = {"gnupg_home": "/var/lib/synapse/ipgp", "identities": [{"mxid": "@me:x.org", "fingerprint": FP}]}


class TestValidConfigurations:
    def test_parses_the_minimal_configuration(self) -> None:
        config = parse_config(MINIMAL)
        assert config.gnupg_home == "/var/lib/synapse/ipgp"
        assert config.identity_for("@me:x.org").fingerprint == FP

    def test_defaults_are_the_safe_ones(self) -> None:
        config = parse_config(MINIMAL)
        # Shipping in enforcing mode would mean a misconfiguration silently eats real messages.
        assert config.dry_run is True
        assert config.identity_for("@me:x.org").policy == POLICY_STRIP
        assert config.ntfy.enabled is False
        assert config.clock_tolerance_sec == 300

    def test_normalises_a_spaced_lowercase_fingerprint(self) -> None:
        spaced = " ".join(FP[i : i + 4] for i in range(0, 40, 4)).lower()
        assert parse_config({**MINIMAL, "identities": [{"mxid": "@me:x.org", "fingerprint": spaced}]}) \
            .identity_for("@me:x.org").fingerprint == FP

    def test_accepts_notify_only_for_a_bridge_ghost(self) -> None:
        config = parse_config({
            **MINIMAL,
            "identities": [
                {"mxid": "@me:x.org", "fingerprint": FP},
                {"mxid": "@instagram_me:x.org", "fingerprint": FP, "policy": POLICY_NOTIFY_ONLY},
            ],
        })
        assert config.identity_for("@instagram_me:x.org").policy == POLICY_NOTIFY_ONLY

    def test_reads_the_ntfy_block(self) -> None:
        config = parse_config({**MINIMAL, "ntfy": {"url": "https://ntfy.sh/t", "token": "tk"}})
        assert config.ntfy.enabled and config.ntfy.token == "tk"

    def test_an_unlisted_sender_has_no_identity(self) -> None:
        assert parse_config(MINIMAL).identity_for("@someone:x.org") is None


class TestRejectedConfigurations:
    @pytest.mark.parametrize(
        "config,because",
        [
            (None, "no config at all"),
            ({}, "no identities"),
            ({"gnupg_home": "/g"}, "identities missing"),
            ({"gnupg_home": "/g", "identities": []}, "identities empty"),
            ({"gnupg_home": "/g", "identities": ["@me:x.org"]}, "identity is not a mapping"),
            ({"identities": [{"mxid": "@me:x.org", "fingerprint": FP}]}, "gnupg_home missing"),
            ({"gnupg_home": "/g", "identities": [{"mxid": "me", "fingerprint": FP}]}, "not an MXID"),
            ({"gnupg_home": "/g", "identities": [{"mxid": "@me:x.org", "fingerprint": "ABC"}]}, "short key id"),
            ({"gnupg_home": "/g", "identities": [{"mxid": "@me:x.org", "fingerprint": FP[:-1] + "Z"}]}, "not hex"),
            ({"gnupg_home": "/g", "identities": [{"mxid": "@me:x.org", "fingerprint": FP, "policy": "burn"}]}, "unknown policy"),
            ({"gnupg_home": "/g", "identities": [{"mxid": "@me:x.org", "fingerprint": FP}] * 2}, "duplicate identity"),
            ({**MINIMAL, "clock_tolerance_sec": -1}, "negative tolerance"),
            ({**MINIMAL, "ntfy": "https://ntfy.sh/t"}, "ntfy is not a mapping"),
        ],
    )
    def test_rejects(self, config, because) -> None:
        with pytest.raises(ConfigError):
            parse_config(config)

    def test_a_short_key_id_is_rejected_with_an_explanation(self) -> None:
        # 16 hex chars is a key id, not a fingerprint, and is too short to identify a key safely.
        with pytest.raises(ConfigError, match="fingerprint"):
            parse_config({"gnupg_home": "/g", "identities": [{"mxid": "@me:x.org", "fingerprint": FP[-16:]}]})
