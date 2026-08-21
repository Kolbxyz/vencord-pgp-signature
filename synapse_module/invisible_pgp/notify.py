# Vencord InvisiblePGP — Synapse module
# SPDX-License-Identifier: GPL-3.0-or-later
"""ntfy alerts.

Strictly best-effort. This runs on the event-persistence path, so a slow or unreachable ntfy must
never delay a message, and a failure to alert must never fail a send — the enforcement decision has
already been made by the time we get here.
"""

from __future__ import annotations

import asyncio
import logging
import urllib.error
import urllib.request

from .config import NtfyConfig

logger = logging.getLogger(__name__)


class Notifier:
    """Posts a short alert to an ntfy topic, off the critical path."""

    def __init__(self, config: NtfyConfig) -> None:
        self._config = config
        #: Held so the tasks are not garbage collected mid-flight, and so tests can await them.
        self._pending: set[asyncio.Task[None]] = set()

    @property
    def enabled(self) -> bool:
        return self._config.enabled

    def notify(self, title: str, message: str, tags: str = "warning") -> None:
        """Fire an alert and return immediately."""
        if not self._config.enabled:
            return

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No loop (a synchronous test, say). Sending inline would block; skipping is correct.
            logger.debug("invisible_pgp: no event loop, dropping ntfy alert %r", title)
            return

        task = loop.create_task(self._send(title, message, tags))
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)

    async def _send(self, title: str, message: str, tags: str) -> None:
        try:
            await asyncio.to_thread(self._post, title, message, tags)
        except Exception:
            # Alerting is a courtesy. Never let it surface into event handling.
            logger.warning("invisible_pgp: could not send ntfy alert", exc_info=True)

    def _post(self, title: str, message: str, tags: str) -> None:
        request = urllib.request.Request(
            self._config.url,  # type: ignore[arg-type]
            data=message.encode("utf-8"),
            method="POST",
            headers={
                "Title": title.encode("utf-8", "replace").decode("latin-1", "replace"),
                "Priority": self._config.priority,
                "Tags": tags,
                **({"Authorization": f"Bearer {self._config.token}"} if self._config.token else {}),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self._config.timeout_sec):
                pass
        except (urllib.error.URLError, OSError) as exc:
            logger.warning("invisible_pgp: ntfy alert failed: %s", exc)

    async def drain(self) -> None:
        """Wait for in-flight alerts. For tests and clean shutdown only."""
        if self._pending:
            await asyncio.gather(*list(self._pending), return_exceptions=True)
