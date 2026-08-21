# Vencord InvisiblePGP — Synapse module
# SPDX-License-Identifier: GPL-3.0-or-later
"""The Synapse module itself.

Registers a ``check_event_allowed`` third-party rule, which is the one callback that can *rewrite*
an event's content and that runs before the event is persisted — and therefore before any bridge
picks it up. That is what makes a single check cover Instagram, Discord, Signal and everything else
bridged into the room, with no per-bridge code.

The decision, in order:

1. not a message, or not from a configured identity  -> allow untouched
2. carries no link and no media                      -> allow untouched  (the common case)
3. carries a link or media, and is validly signed    -> allow untouched
4. otherwise                                         -> alert, and strip unless dry-run
"""

from __future__ import annotations

import logging
import time
from typing import Any, Awaitable, Callable

from .binding import MessageContext, canonical_signed_text, is_usable_context
from .codec import decode_message
from .config import POLICY_STRIP, Identity, ModuleConfig, parse_config
from .notify import Notifier
from .strip import carries_link_or_media, media_reference, strip_content
from .verify import SignatureVerifier, Verdict

logger = logging.getLogger(__name__)

#: What Synapse expects back: (allowed, replacement_content_or_None).
CheckResult = tuple[bool, dict[str, Any] | None]

#: Every event we look at. Everything else is someone else's business.
_MESSAGE_TYPE = "m.room.message"

_ALLOW: CheckResult = (True, None)


class SignatureEnforcer:
    """Holds unsigned links and media from configured accounts out of the room."""

    def __init__(self, config: dict[str, Any], api: Any) -> None:
        self._config: ModuleConfig = parse_config(config)
        self._api = api
        self._verifier = SignatureVerifier(
            gnupg_home=self._config.gnupg_home,
            gpg_binary=self._config.gpg_binary,
            timeout_sec=self._config.gpg_timeout_sec,
        )
        self._notifier = Notifier(self._config.ntfy)

        if api is not None:
            api.register_third_party_rules_callbacks(check_event_allowed=self.check_event_allowed)

        logger.info(
            "invisible_pgp: watching %d identit%s, dry_run=%s, ntfy=%s",
            len(self._config.identities),
            "y" if len(self._config.identities) == 1 else "ies",
            self._config.dry_run,
            "on" if self._notifier.enabled else "off",
        )
        if self._config.dry_run:
            logger.warning(
                "invisible_pgp: dry_run is on — failures are reported but nothing is stripped. "
                "Set dry_run: false once you are happy with what it reports."
            )

    # -- Synapse entry point ------------------------------------------------------------------

    async def check_event_allowed(self, event: Any, state: Any = None) -> CheckResult:
        """Never raises. A crash here would take down message sending for the whole homeserver."""
        try:
            return self._decide(event)
        except Exception:
            logger.exception("invisible_pgp: check failed, allowing the event through unchanged")
            return _ALLOW

    # -- The decision -------------------------------------------------------------------------

    def _decide(self, event: Any) -> CheckResult:
        if getattr(event, "type", None) != _MESSAGE_TYPE:
            return _ALLOW

        sender = getattr(event, "sender", None)
        identity = self._config.identity_for(sender) if isinstance(sender, str) else None
        if identity is None:
            return _ALLOW

        content = getattr(event, "content", None)
        if not isinstance(content, dict):
            return _ALLOW

        # Plain conversation is exempt. This is what lets the scheme work without a signing client
        # on Matrix: only the messages that could actually do harm have to carry a signature.
        if not carries_link_or_media(content):
            return _ALLOW

        reason = self._check_signature(event, identity, content)
        if reason is None:
            return _ALLOW

        return self._enforce(event, identity, content, reason)

    def _check_signature(self, event: Any, identity: Identity, content: dict[str, Any]) -> str | None:
        """Return ``None`` when the event is properly signed, else why it is not."""
        body = content.get("body")
        if not isinstance(body, str):
            return "message has no text body to verify"

        decoded = decode_message(body)
        if decoded.frame is None:
            return "no signature"

        frame = decoded.frame
        if frame.timestamp is None:
            # An unbound signature proves only that the text was signed at some point, by someone.
            # It cannot tie the message to this room, this sender or this moment, so it is not
            # evidence that this message is genuine.
            return "signature is not bound to a room, sender and time"

        posted_at = int(getattr(event, "origin_server_ts", 0) or 0) // 1000 or int(time.time())
        drift = abs(posted_at - frame.timestamp)
        if drift > self._config.clock_tolerance_sec:
            return f"signed {drift}s away from when it was posted (possible replay)"

        ctx = MessageContext(
            platform="matrix",
            conversation_id=str(getattr(event, "room_id", "")),
            author_id=identity.mxid,
            timestamp=frame.timestamp,
            # Binds the file itself, not just its name. Otherwise a captured signed image could
            # keep its signature while being repointed at different content.
            attachment=media_reference(content),
        )
        if not is_usable_context(ctx):
            return "could not determine the room this message belongs to"

        signed_text = canonical_signed_text(ctx, decoded.visible_text, frame.version)
        result = self._verifier.verify(frame.sig, signed_text, identity.fingerprint)

        if result.ok:
            return None
        if result.verdict is Verdict.ERROR:
            # An unverifiable message is not a verified one. Failing open here would mean a
            # misconfigured gpg silently switches the whole feature off.
            logger.error("invisible_pgp: verification error: %s", result.detail)
        return f"{result.verdict.value}: {result.detail}" if result.detail else result.verdict.value

    def _enforce(
        self, event: Any, identity: Identity, content: dict[str, Any], reason: str
    ) -> CheckResult:
        room_id = getattr(event, "room_id", "?")
        would_strip = identity.policy == POLICY_STRIP and not self._config.dry_run

        logger.warning(
            "invisible_pgp: %s in %s — %s (%s)",
            identity.mxid,
            room_id,
            reason,
            "stripping" if would_strip else "reporting only",
        )

        self._notifier.notify(
            title=f"Unsigned link from {identity.mxid}",
            message=(
                f"{reason}\n"
                f"room: {room_id}\n"
                f"action: {'links and media stripped' if would_strip else 'left in place'}"
            ),
        )

        if not would_strip:
            return _ALLOW

        return (True, strip_content(content))
