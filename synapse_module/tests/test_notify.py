# Vencord InvisiblePGP — Synapse module
# SPDX-License-Identifier: GPL-3.0-or-later
"""ntfy alerting.

The only property that really matters: alerting is best-effort and must never affect the
enforcement path. A homeserver that fails to deliver messages because ntfy is down is worse than
one that quietly fails to alert.
"""

from __future__ import annotations

import pytest

from invisible_pgp.config import NtfyConfig
from invisible_pgp.notify import Notifier

pytestmark = pytest.mark.asyncio


async def test_disabled_when_no_url_is_configured() -> None:
    notifier = Notifier(NtfyConfig())
    assert not notifier.enabled
    notifier.notify("title", "message")  # must not raise
    await notifier.drain()


async def test_posts_to_the_configured_topic(monkeypatch) -> None:
    sent: list[dict] = []
    notifier = Notifier(NtfyConfig(url="https://ntfy.example/topic", token="tk", priority="high"))
    monkeypatch.setattr(
        notifier, "_post",
        lambda title, message, tags: sent.append({"title": title, "message": message, "tags": tags}),
    )

    notifier.notify("Unsigned link", "details here")
    await notifier.drain()

    assert sent == [{"title": "Unsigned link", "message": "details here", "tags": "warning"}]


async def test_a_failing_notifier_never_raises(monkeypatch) -> None:
    notifier = Notifier(NtfyConfig(url="https://ntfy.example/topic"))

    def explode(*_args, **_kwargs):
        raise RuntimeError("ntfy is down")

    monkeypatch.setattr(notifier, "_post", explode)

    notifier.notify("title", "message")
    await notifier.drain()  # the failure is swallowed and logged, not propagated


async def test_returns_immediately_rather_than_blocking(monkeypatch) -> None:
    import time as _time

    notifier = Notifier(NtfyConfig(url="https://ntfy.example/topic", timeout_sec=0.05))
    monkeypatch.setattr(notifier, "_post", lambda *a, **k: _time.sleep(0.2))

    started = _time.perf_counter()
    notifier.notify("title", "message")
    elapsed = _time.perf_counter() - started

    # The event path must not wait on the network.
    assert elapsed < 0.05
    await notifier.drain()


@pytest.mark.asyncio(loop_scope="function")
async def test_notifying_without_an_event_loop_is_a_no_op() -> None:
    # Exercised via asyncio.to_thread so the callee genuinely has no running loop.
    import asyncio
    notifier = Notifier(NtfyConfig(url="https://ntfy.example/topic"))
    # A synchronous context has no loop to schedule on; sending inline would block.
    await asyncio.to_thread(notifier.notify, "title", "message")
