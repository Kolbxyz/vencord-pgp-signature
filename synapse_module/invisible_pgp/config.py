# Vencord InvisiblePGP — Synapse module
# SPDX-License-Identifier: GPL-3.0-or-later
"""Module configuration, parsed and validated once at startup.

Every error here is raised while Synapse is loading rather than when the first message arrives.
A homeserver that starts with a broken signature policy and only reveals it under traffic is worse
than one that refuses to start.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

#: What to do with an event from a configured identity that fails verification.
POLICY_STRIP = "strip"
POLICY_NOTIFY_ONLY = "notify_only"
POLICIES = (POLICY_STRIP, POLICY_NOTIFY_ONLY)

_MXID_RE = re.compile(r"^@[^:]+:.+$")
_FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}$")


class ConfigError(ValueError):
    """Raised for a configuration that cannot be honoured."""


@dataclass(frozen=True)
class Identity:
    """An account whose links and media must be signed."""

    mxid: str
    fingerprint: str
    #: ``strip`` removes links and media; ``notify_only`` alerts but changes nothing.
    #:
    #: ``notify_only`` exists for bridge ghosts. A ghost such as ``@instagram_me:server`` can never
    #: produce a signature — nothing on the far side of the bridge can sign — so holding one to
    #: ``strip`` would eat every link you legitimately post from that account. Watching it and
    #: saying so is the useful behaviour; blocking it is not.
    policy: str = POLICY_STRIP


@dataclass(frozen=True)
class NtfyConfig:
    url: str | None = None
    token: str | None = None
    timeout_sec: float = 5.0
    priority: str = "high"

    @property
    def enabled(self) -> bool:
        return bool(self.url)


@dataclass(frozen=True)
class ModuleConfig:
    identities: dict[str, Identity]
    gnupg_home: str
    gpg_binary: str = "gpg"
    gpg_timeout_sec: int = 10
    #: How far the sender's clock may sit from the server's, in seconds.
    clock_tolerance_sec: int = 300
    #: When true, verify and notify but never modify an event. The shipped default.
    dry_run: bool = True
    ntfy: NtfyConfig = field(default_factory=NtfyConfig)

    def identity_for(self, mxid: str) -> Identity | None:
        return self.identities.get(mxid)


def _require(config: dict[str, Any], key: str) -> Any:
    if key not in config:
        raise ConfigError(f"invisible_pgp: missing required setting {key!r}")
    return config[key]


def parse_config(config: dict[str, Any] | None) -> ModuleConfig:
    """Validate the ``config`` block from ``homeserver.yaml``."""
    config = config or {}

    raw_identities = _require(config, "identities")
    if not isinstance(raw_identities, list) or not raw_identities:
        raise ConfigError("invisible_pgp: 'identities' must be a non-empty list")

    identities: dict[str, Identity] = {}
    for entry in raw_identities:
        if not isinstance(entry, dict):
            raise ConfigError("invisible_pgp: each identity must be a mapping")

        mxid = str(entry.get("mxid", "")).strip()
        if not _MXID_RE.match(mxid):
            raise ConfigError(f"invisible_pgp: {mxid!r} is not a valid MXID (expected @user:server)")

        fingerprint = str(entry.get("fingerprint", "")).replace(" ", "").upper()
        if not _FINGERPRINT_RE.match(fingerprint):
            raise ConfigError(
                f"invisible_pgp: identity {mxid} needs a full 40-character hex fingerprint, "
                "not a short key id — a key id is too short to identify a key safely"
            )

        policy = str(entry.get("policy", POLICY_STRIP))
        if policy not in POLICIES:
            raise ConfigError(
                f"invisible_pgp: identity {mxid} has unknown policy {policy!r}; "
                f"expected one of {', '.join(POLICIES)}"
            )

        if mxid in identities:
            raise ConfigError(f"invisible_pgp: identity {mxid} is listed twice")

        identities[mxid] = Identity(mxid=mxid, fingerprint=fingerprint, policy=policy)

    ntfy_raw = config.get("ntfy") or {}
    if not isinstance(ntfy_raw, dict):
        raise ConfigError("invisible_pgp: 'ntfy' must be a mapping")

    ntfy = NtfyConfig(
        url=ntfy_raw.get("url"),
        token=ntfy_raw.get("token"),
        timeout_sec=float(ntfy_raw.get("timeout_sec", 5.0)),
        priority=str(ntfy_raw.get("priority", "high")),
    )

    clock_tolerance = int(config.get("clock_tolerance_sec", 300))
    if clock_tolerance < 0:
        raise ConfigError("invisible_pgp: 'clock_tolerance_sec' cannot be negative")

    return ModuleConfig(
        identities=identities,
        gnupg_home=str(_require(config, "gnupg_home")),
        gpg_binary=str(config.get("gpg_binary", "gpg")),
        gpg_timeout_sec=int(config.get("gpg_timeout_sec", 10)),
        clock_tolerance_sec=clock_tolerance,
        dry_run=bool(config.get("dry_run", True)),
        ntfy=ntfy,
    )
