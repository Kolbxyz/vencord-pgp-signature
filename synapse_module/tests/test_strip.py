# Vencord InvisiblePGP — Synapse module
# SPDX-License-Identifier: GPL-3.0-or-later
"""Link and media detection, and the rewriting that follows it.

Detection and stripping have to agree: anything flagged must be something that can actually be
removed, or a message gets blocked and still shows the link.
"""

from __future__ import annotations

import pytest

from invisible_pgp.strip import (
    MEDIA_MSGTYPES, REDACTION_NOTICE, carries_link_or_media, media_reference, strip_content,
)

text = lambda body, **extra: {"msgtype": "m.text", "body": body, **extra}


class TestDetection:
    @pytest.mark.parametrize("body", [
        "https://example.org/page", "HTTP://EXAMPLE.ORG", "http://a.b", "www.example.org",
        "evil.com/path", "bit.ly/xyz", "sub.domain.co.uk/p", "foo.com:8080/x", "1.2.3.4",
        "mxc://server/media", "ftp://files.example.org/x", "mailto:someone@example.org",
        "look at this: example.org", "magnet:?xt=urn:btih:abc",
    ])
    def test_flags_things_that_are_links(self, body) -> None:
        assert carries_link_or_media(text(body)), body

    @pytest.mark.parametrize("body", [
        "", "hello, how are you", "I ❤️ you 👍🏽", "see notes.txt", "version 1.2.3",
        "e.g. this one", "my file.zip", "someone@example.org", "a@b.com",
        "10 x 20 = 200", "ratio 16.9",
    ])
    def test_does_not_flag_ordinary_text(self, body) -> None:
        # A false positive is not harmless: it strips a message that was perfectly fine.
        assert not carries_link_or_media(text(body)), body

    @pytest.mark.parametrize("msgtype", sorted(MEDIA_MSGTYPES))
    def test_flags_every_media_msgtype(self, msgtype) -> None:
        assert carries_link_or_media({"msgtype": msgtype, "body": "file", "url": "mxc://x/y"})

    def test_flags_a_link_that_only_appears_in_the_html_body(self) -> None:
        assert carries_link_or_media(
            text("click here", format="org.matrix.custom.html",
                 formatted_body='click <a href="https://evil.example.org">here</a>')
        )

    @pytest.mark.parametrize("tag", ["img", "video", "audio", "iframe", "embed", "object"])
    def test_flags_embedded_media_in_html(self, tag) -> None:
        assert carries_link_or_media(text("x", formatted_body=f'<{tag} src="https://e.org/a" />'))

    def test_flags_encrypted_media_referenced_under_file(self) -> None:
        assert carries_link_or_media({"msgtype": "m.text", "body": "x", "file": {"url": "mxc://x/y"}})

    def test_tolerates_content_without_a_body(self) -> None:
        assert not carries_link_or_media({"msgtype": "m.text"})


class TestStripping:
    def test_removes_a_url_from_the_plain_body(self) -> None:
        out = strip_content(text("click https://evil.example.org/x now"))
        assert "evil.example.org" not in out["body"]
        assert REDACTION_NOTICE in out["body"]
        assert out["body"].startswith("click ") and out["body"].endswith(" now")

    def test_removes_the_anchor_but_keeps_what_the_sender_wrote(self) -> None:
        out = strip_content(text("click here", formatted_body='say <b>hi</b> <a href="https://e.org">here</a>'))
        assert "<a" not in out["formatted_body"]
        assert "e.org" not in out["formatted_body"]
        assert "<b>hi</b>" in out["formatted_body"], "ordinary markup must survive"
        assert "here" in out["formatted_body"], "the anchor's text is the sender's own words"

    def test_removes_an_embedded_image(self) -> None:
        out = strip_content(text("x", formatted_body='<p>see <img src="https://e.org/a.png"></p>'))
        assert "e.org" not in out["formatted_body"]
        assert "<p>" in out["formatted_body"]

    def test_removes_a_url_written_out_inside_html_text(self) -> None:
        out = strip_content(text("x", formatted_body="<p>go to https://evil.example.org/x</p>"))
        assert "evil.example.org" not in out["formatted_body"]

    @pytest.mark.parametrize("msgtype", sorted(MEDIA_MSGTYPES))
    def test_media_becomes_a_notice_with_every_handle_dropped(self, msgtype) -> None:
        out = strip_content({
            "msgtype": msgtype, "body": "holiday.png", "url": "mxc://x/y",
            "info": {"w": 1}, "thumbnail_url": "mxc://x/t", "file": {"url": "mxc://x/z"},
        })
        assert out["msgtype"] == "m.text"
        assert out["body"] == REDACTION_NOTICE
        for key in ("url", "file", "info", "thumbnail_url"):
            assert key not in out, f"{key} would still point at the media"

    def test_strips_the_replacement_content_of_an_edit(self) -> None:
        # Otherwise the link simply reappears inside m.new_content.
        out = strip_content(text("x", **{"m.new_content": text("go to https://evil.example.org")}))
        assert "evil.example.org" not in out["m.new_content"]["body"]

    def test_does_not_mutate_the_content_it_was_given(self) -> None:
        original = text("click https://evil.example.org")
        strip_content(original)
        assert original["body"] == "click https://evil.example.org"

    def test_leaves_text_without_links_alone(self) -> None:
        assert strip_content(text("hello there"))["body"] == "hello there"


class TestMediaReference:
    def test_reads_a_plain_url(self) -> None:
        assert media_reference({"url": "mxc://x/y"}) == "mxc://x/y"

    def test_reads_an_encrypted_files_url(self) -> None:
        assert media_reference({"file": {"url": "mxc://x/z"}}) == "mxc://x/z"

    def test_is_empty_when_there_is_no_media(self) -> None:
        assert media_reference({"body": "hi"}) == ""
        assert media_reference({"file": "not a mapping"}) == ""
