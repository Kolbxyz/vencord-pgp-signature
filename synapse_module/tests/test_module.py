# Vencord InvisiblePGP — Synapse module
# SPDX-License-Identifier: GPL-3.0-or-later
"""The enforcement decision, end to end, against real gpg signatures.

These are the tests that matter operationally: every one of them corresponds to a message the
homeserver will either pass through or rewrite in production.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import pytest

from invisible_pgp.binding import MessageContext, canonical_signed_text
from invisible_pgp.codec import BASE16, encode_payload
from invisible_pgp.module import SignatureEnforcer
from invisible_pgp.strip import REDACTION_NOTICE

from conftest import SigningKey, requires_gpg

ME = "@me:example.org"
ROOM = "!room:example.org"
LINK = "https://example.org/some/page"


@dataclass
class FakeEvent:
    """The handful of attributes the module reads off a Synapse event."""

    content: dict[str, Any]
    sender: str = ME
    room_id: str = ROOM
    type: str = "m.room.message"
    origin_server_ts: int = field(default_factory=lambda: int(time.time()) * 1000)


def make_enforcer(keyring: str, fingerprint: str, **overrides: Any) -> SignatureEnforcer:
    config: dict[str, Any] = {
        "gnupg_home": keyring,
        "dry_run": False,
        "identities": [{"mxid": ME, "fingerprint": fingerprint}],
    }
    config.update(overrides)
    return SignatureEnforcer(config, api=None)


def sign_body(
    key: SigningKey, text: str, ts: int, room: str = ROOM, sender: str = ME, attachment: str = ""
) -> str:
    """Produce the body a signing client would send."""
    ctx = MessageContext(
        platform="matrix", conversation_id=room, author_id=sender, timestamp=ts, attachment=attachment
    )
    signature = key.sign(canonical_signed_text(ctx, text))
    return text + encode_payload(signature, BASE16, key.fingerprint[-16:], ts)


async def decide(enforcer: SignatureEnforcer, event: FakeEvent):
    return await enforcer.check_event_allowed(event)


pytestmark = pytest.mark.asyncio


class TestPassThrough:
    """Cases the module must not touch. A false positive here eats a real message."""

    @requires_gpg
    async def test_plain_text_needs_no_signature(self, keyring, signer) -> None:
        enforcer = make_enforcer(keyring, signer.fingerprint)
        event = FakeEvent({"msgtype": "m.text", "body": "hello, how are you"})
        assert await decide(enforcer, event) == (True, None)

    @requires_gpg
    async def test_text_containing_an_emoji_is_still_plain_text(self, keyring, signer) -> None:
        enforcer = make_enforcer(keyring, signer.fingerprint)
        event = FakeEvent({"msgtype": "m.text", "body": "I ❤️ you 👍🏽"})
        assert await decide(enforcer, event) == (True, None)

    @requires_gpg
    async def test_another_sender_is_none_of_our_business(self, keyring, signer) -> None:
        enforcer = make_enforcer(keyring, signer.fingerprint)
        event = FakeEvent({"msgtype": "m.text", "body": LINK}, sender="@someone:example.org")
        assert await decide(enforcer, event) == (True, None)

    @requires_gpg
    async def test_non_message_events_are_ignored(self, keyring, signer) -> None:
        enforcer = make_enforcer(keyring, signer.fingerprint)
        event = FakeEvent({"body": LINK}, type="m.room.topic")
        assert await decide(enforcer, event) == (True, None)

    @requires_gpg
    async def test_a_correctly_signed_link_passes_untouched(self, keyring, signer) -> None:
        enforcer = make_enforcer(keyring, signer.fingerprint)
        now = int(time.time())
        body = sign_body(signer, f"look at this {LINK}", now)
        event = FakeEvent({"msgtype": "m.text", "body": body}, origin_server_ts=now * 1000)
        assert await decide(enforcer, event) == (True, None)

    @requires_gpg
    async def test_a_correctly_signed_image_passes_untouched(self, keyring, signer) -> None:
        enforcer = make_enforcer(keyring, signer.fingerprint)
        now = int(time.time())
        event = FakeEvent(
            {
                "msgtype": "m.image",
                "body": sign_body(signer, "holiday.png", now, attachment="mxc://x/y"),
                "url": "mxc://x/y",
            },
            origin_server_ts=now * 1000,
        )
        assert await decide(enforcer, event) == (True, None)

    @requires_gpg
    async def test_a_signed_image_cannot_have_its_file_swapped(self, keyring, signer) -> None:
        # The signature covers the mxc URI, not just the caption, so keeping a captured signature
        # while repointing it at different content must fail.
        enforcer = make_enforcer(keyring, signer.fingerprint)
        now = int(time.time())
        event = FakeEvent(
            {
                "msgtype": "m.image",
                "body": sign_body(signer, "holiday.png", now, attachment="mxc://x/original"),
                "url": "mxc://x/swapped",
            },
            origin_server_ts=now * 1000,
        )
        _, replacement = await decide(enforcer, event)
        assert replacement is not None


class TestEnforcement:
    """Cases the module must act on."""

    @requires_gpg
    async def test_an_unsigned_link_is_stripped(self, keyring, signer) -> None:
        enforcer = make_enforcer(keyring, signer.fingerprint)
        allowed, replacement = await decide(
            enforcer, FakeEvent({"msgtype": "m.text", "body": f"click {LINK}"})
        )
        assert allowed is True
        assert replacement is not None
        assert LINK not in replacement["body"]
        assert REDACTION_NOTICE in replacement["body"]

    @requires_gpg
    async def test_an_unsigned_image_becomes_a_notice_with_no_url(self, keyring, signer) -> None:
        enforcer = make_enforcer(keyring, signer.fingerprint)
        _, replacement = await decide(
            enforcer, FakeEvent({"msgtype": "m.image", "body": "cat.png", "url": "mxc://x/y"})
        )
        assert replacement["msgtype"] == "m.text"
        assert "url" not in replacement
        assert replacement["body"] == REDACTION_NOTICE

    @requires_gpg
    async def test_a_link_hidden_in_formatted_body_is_stripped_too(self, keyring, signer) -> None:
        # The case that matters most: stripping only `body` leaves the link live in every client
        # that renders HTML, which is most of them.
        enforcer = make_enforcer(keyring, signer.fingerprint)
        _, replacement = await decide(enforcer, FakeEvent({
            "msgtype": "m.text",
            "body": "click here",
            "format": "org.matrix.custom.html",
            "formatted_body": f'click <a href="{LINK}">here</a>',
        }))
        assert replacement is not None
        assert LINK not in replacement["formatted_body"]
        assert "<a" not in replacement["formatted_body"]

    @requires_gpg
    async def test_a_tampered_message_is_stripped(self, keyring, signer) -> None:
        enforcer = make_enforcer(keyring, signer.fingerprint)
        now = int(time.time())
        body = sign_body(signer, f"look at this {LINK}", now)
        tampered = body.replace("example.org/some/page", "evil.example.com/phish")

        allowed, replacement = await decide(
            enforcer, FakeEvent({"msgtype": "m.text", "body": tampered}, origin_server_ts=now * 1000)
        )
        assert replacement is not None
        assert "evil" not in replacement["body"]

    @requires_gpg
    async def test_a_signature_from_another_key_is_rejected(self, keyring, signer, impostor) -> None:
        # Both keys are in the keyring, so this proves the module checks *which* key signed rather
        # than merely that some trusted key did.
        enforcer = make_enforcer(keyring, signer.fingerprint)
        now = int(time.time())
        body = sign_body(impostor, f"trust me {LINK}", now)

        _, replacement = await decide(
            enforcer, FakeEvent({"msgtype": "m.text", "body": body}, origin_server_ts=now * 1000)
        )
        assert replacement is not None, "a signature by the wrong key must not be accepted"

    @requires_gpg
    async def test_a_signature_for_another_room_is_rejected(self, keyring, signer) -> None:
        enforcer = make_enforcer(keyring, signer.fingerprint)
        now = int(time.time())
        body = sign_body(signer, f"see {LINK}", now, room="!elsewhere:example.org")

        _, replacement = await decide(
            enforcer, FakeEvent({"msgtype": "m.text", "body": body}, origin_server_ts=now * 1000)
        )
        assert replacement is not None, "context binding must reject a message moved between rooms"

    @requires_gpg
    async def test_a_replayed_signature_is_rejected(self, keyring, signer) -> None:
        enforcer = make_enforcer(keyring, signer.fingerprint)
        old = int(time.time()) - 86_400
        body = sign_body(signer, f"see {LINK}", old)

        _, replacement = await decide(
            enforcer,
            FakeEvent({"msgtype": "m.text", "body": body}, origin_server_ts=int(time.time()) * 1000),
        )
        assert replacement is not None, "an old signature must not be replayable"

    @requires_gpg
    async def test_an_unbound_signature_is_not_enough(self, keyring, signer) -> None:
        # No timestamp means the signature cannot be tied to this room, sender or moment.
        enforcer = make_enforcer(keyring, signer.fingerprint)
        text = f"see {LINK}"
        body = text + encode_payload(signer.sign(text), BASE16, signer.fingerprint[-16:], None)

        _, replacement = await decide(enforcer, FakeEvent({"msgtype": "m.text", "body": body}))
        assert replacement is not None


class TestDryRun:
    @requires_gpg
    async def test_dry_run_reports_but_never_modifies(self, keyring, signer) -> None:
        enforcer = make_enforcer(keyring, signer.fingerprint, dry_run=True)
        assert await decide(
            enforcer, FakeEvent({"msgtype": "m.text", "body": f"click {LINK}"})
        ) == (True, None)

    @requires_gpg
    async def test_dry_run_is_the_shipped_default(self, keyring, signer) -> None:
        enforcer = SignatureEnforcer(
            {"gnupg_home": keyring, "identities": [{"mxid": ME, "fingerprint": signer.fingerprint}]},
            api=None,
        )
        assert await decide(
            enforcer, FakeEvent({"msgtype": "m.text", "body": f"click {LINK}"})
        ) == (True, None)

    @requires_gpg
    async def test_notify_only_identities_are_never_stripped(self, keyring, signer) -> None:
        enforcer = make_enforcer(
            keyring, signer.fingerprint,
            identities=[{"mxid": ME, "fingerprint": signer.fingerprint, "policy": "notify_only"}],
        )
        assert await decide(
            enforcer, FakeEvent({"msgtype": "m.text", "body": f"click {LINK}"})
        ) == (True, None)


class TestRobustness:
    @requires_gpg
    async def test_a_broken_event_never_takes_down_message_sending(self, keyring, signer) -> None:
        enforcer = make_enforcer(keyring, signer.fingerprint)

        class Exploding:
            type = "m.room.message"
            sender = ME

            @property
            def content(self):
                raise RuntimeError("boom")

        assert await decide(enforcer, Exploding()) == (True, None)

    @requires_gpg
    async def test_a_missing_gpg_binary_blocks_rather_than_silently_allows(self, keyring, signer) -> None:
        # Failing open would mean a misconfigured gpg quietly switches the feature off.
        enforcer = make_enforcer(keyring, signer.fingerprint, gpg_binary="/nonexistent/gpg")
        now = int(time.time())
        body = sign_body(signer, f"see {LINK}", now)

        _, replacement = await decide(
            enforcer, FakeEvent({"msgtype": "m.text", "body": body}, origin_server_ts=now * 1000)
        )
        assert replacement is not None

    @requires_gpg
    async def test_content_that_is_not_a_dict_is_ignored(self, keyring, signer) -> None:
        enforcer = make_enforcer(keyring, signer.fingerprint)
        assert await decide(enforcer, FakeEvent(content=None)) == (True, None)  # type: ignore[arg-type]
