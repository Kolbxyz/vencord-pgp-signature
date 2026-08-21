# Vencord InvisiblePGP — Synapse module
# SPDX-License-Identifier: GPL-3.0-or-later
"""Deciding whether an event carries a link or media, and removing them when it does.

Two jobs, kept together because they must agree: anything :func:`carries_link_or_media` flags has
to be something :func:`strip_content` can actually remove. If detection is broader than stripping,
a message gets blocked and still shows the link.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any

#: Message types that are media by definition, whatever their body says.
MEDIA_MSGTYPES = frozenset({"m.image", "m.video", "m.audio", "m.file"})

#: What replaces a stripped link or media item. Visible on purpose: silently deleting content
#: would be worse than saying that something was removed and why.
REDACTION_NOTICE = "[removed: unsigned link or media]"

#: Bare-ish URL matcher. Intentionally generous — over-matching costs a false "this needs a
#: signature", which is safe, while under-matching lets an unsigned link through, which is not.
#: Common TLDs, plus anything an explicit scheme or "www." already makes unambiguous.
#:
#: A closed list rather than "any dotted word": matching every ``label.label`` would flag ordinary
#: text like "see notes.txt" as a link, and a false positive here does not merely warn — it strips
#: a message that was fine. Over-matching *within* plausible domains is safe; over-matching across
#: all dotted words is not.
_TLDS = (
    "com|net|org|edu|gov|mil|int|info|biz|name|pro|xyz|top|site|online|store|shop|app|dev|io|ai"
    "|co|me|tv|cc|gg|gl|ly|to|sh|st|fm|am|im|is|it|in|id|se|no|fi|dk|nl|be|de|fr|es|pt|pl|cz|sk"
    "|at|ch|hu|ro|bg|gr|tr|ru|ua|by|kz|uk|ie|eu|us|ca|mx|br|ar|cl|pe|au|nz|jp|kr|cn|hk|tw|sg|my"
    "|th|vn|ph|id|za|ng|ke|eg|ma|il|ae|sa|ir|pk|bd|lk|np|link|click|page|blog|wiki|news|live|life"
    "|world|space|cloud|host|website|email|chat|social|media|video|photo|art|design|studio|agency"
    "|systems|network|digital|tech|software|codes|zone|run|sh|gift|fun|lol|wtf|pizza|ninja|guru"
)

#: Bare-ish URL matcher. Intentionally generous within each branch — an unsigned link that slips
#: through is a failure of the whole feature, while a needlessly flagged message merely asks for a
#: signature it should have had anyway.
_URL_RE = re.compile(
    rf"""(?xi)
    (?<![\w@.])                                       # not mid-word, and not an email local part
    (
        (?:https?|ftp|ftps|matrix|mailto|xmpp|tel|magnet|data):[^\s<>"']+
      | mxc://[^\s<>"']+                              # Matrix media
      | www\.[^\s<>"']+                              # scheme-less but unmistakable
      | (?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+        # one or more labels, then a known TLD
        (?:{_TLDS})\b
        (?::\d{{1,5}})?
        (?:/[^\s<>"']*)?
      | \b(?:\d{{1,3}}\.){{3}}\d{{1,3}}                # bare IPv4, with or without a path
        (?::\d{{1,5}})?
        (?:/[^\s<>"']*)?
    )
    """
)

_LINKING_TAGS = {"a", "img", "video", "audio", "source", "iframe", "embed", "object"}


class _LinkFinder(HTMLParser):
    """Spots linking or embedding tags in an HTML body."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.found = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _LINKING_TAGS:
            self.found = True


class _LinkStripper(HTMLParser):
    """Rewrites an HTML body with linking tags removed.

    Anchor *text* is kept — it is what the sender wrote — while the link itself is dropped and
    replaced by a notice. Embedded media is replaced outright, since there is no text to keep.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self._suppress_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self.out.append(f"{REDACTION_NOTICE} ")
            self._suppress_depth += 1
            return
        if tag in _LINKING_TAGS:
            self.out.append(REDACTION_NOTICE)
            return
        if self._suppress_depth:
            return
        self.out.append(self._render_start(tag, attrs))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _LINKING_TAGS:
            self.out.append(REDACTION_NOTICE)
            return
        if self._suppress_depth:
            return
        self.out.append(self._render_start(tag, attrs, self_closing=True))

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            self._suppress_depth = max(0, self._suppress_depth - 1)
            return
        if tag in _LINKING_TAGS or self._suppress_depth:
            return
        self.out.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        # Text inside an anchor is kept, but any URL written out in full still has to go.
        self.out.append(_URL_RE.sub(REDACTION_NOTICE, data))

    @staticmethod
    def _render_start(
        tag: str, attrs: list[tuple[str, str | None]], self_closing: bool = False
    ) -> str:
        rendered = "".join(
            f' {name}="{_escape_attr(value)}"' for name, value in attrs if value is not None
        )
        return f"<{tag}{rendered}{'/' if self_closing else ''}>"


def _escape_attr(value: str) -> str:
    return value.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")


def media_reference(content: dict[str, Any]) -> str:
    """The identifier of the media this event carries, or "" when it carries none.

    This is the value bound into the signature, so it has to name the *content*, not the caption.
    Encrypted media puts its URI under ``file.url`` rather than ``url``.
    """
    url = content.get("url")
    if isinstance(url, str):
        return url

    file_info = content.get("file")
    if isinstance(file_info, dict):
        nested = file_info.get("url")
        if isinstance(nested, str):
            return nested

    return ""


def carries_link_or_media(content: dict[str, Any]) -> bool:
    """True when the event is one that must be signed to be allowed through.

    Plain conversational text is exempt, which is what keeps the whole scheme usable without a
    signing client on the Matrix side.
    """
    if content.get("msgtype") in MEDIA_MSGTYPES:
        return True
    if isinstance(content.get("url"), str) or isinstance(content.get("file"), dict):
        return True

    body = content.get("body")
    if isinstance(body, str) and _URL_RE.search(body):
        return True

    formatted = content.get("formatted_body")
    if isinstance(formatted, str):
        if _URL_RE.search(formatted):
            return True
        finder = _LinkFinder()
        finder.feed(formatted)
        if finder.found:
            return True

    return False


def strip_content(content: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``content`` with links and media removed.

    Both bodies are rewritten. Doing only ``body`` would leave the link live in every client that
    renders ``formatted_body``, which is most of them.
    """
    stripped = dict(content)

    if content.get("msgtype") in MEDIA_MSGTYPES:
        # There is nothing to keep: the payload *is* the media. Downgrade it to a notice so the
        # room still shows that something was said, and drop every handle to the file.
        stripped["msgtype"] = "m.text"
        stripped["body"] = REDACTION_NOTICE
        for key in ("url", "file", "info", "thumbnail_url", "thumbnail_file", "thumbnail_info"):
            stripped.pop(key, None)
        stripped.pop("formatted_body", None)
        stripped.pop("format", None)
        return stripped

    body = content.get("body")
    if isinstance(body, str):
        stripped["body"] = _URL_RE.sub(REDACTION_NOTICE, body)

    formatted = content.get("formatted_body")
    if isinstance(formatted, str):
        stripper = _LinkStripper()
        stripper.feed(formatted)
        stripper.close()
        stripped["formatted_body"] = "".join(stripper.out)

    # A reply or edit carries a copy of the original content, which must be stripped too or the
    # link simply reappears inside the fallback.
    for nested_key in ("m.new_content",):
        nested = content.get(nested_key)
        if isinstance(nested, dict):
            stripped[nested_key] = strip_content(nested)

    return stripped
