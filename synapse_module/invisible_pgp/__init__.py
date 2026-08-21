# Vencord InvisiblePGP — Synapse module
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify InvisiblePGP signatures on a Synapse homeserver.

Load it from ``homeserver.yaml``::

    modules:
      - module: invisible_pgp.SignatureEnforcer
        config:
          gnupg_home: /var/lib/synapse/invisible_pgp/gnupg
          dry_run: true
          identities:
            - mxid: "@me:example.org"
              fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567"

See ``synapse_module/README.md`` for the full set of options.
"""

from .config import Identity, ModuleConfig, NtfyConfig, parse_config
from .module import SignatureEnforcer
from .verify import Verdict, VerifyResult

__all__ = [
    "Identity",
    "ModuleConfig",
    "NtfyConfig",
    "SignatureEnforcer",
    "Verdict",
    "VerifyResult",
    "parse_config",
]
