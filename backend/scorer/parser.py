"""Turns raw RFC 822 bytes into a small, safe-to-use structure.

Everything here is untrusted input. Rules we follow:
- size limits on the whole message and on what we inspect inside archives;
- attachments are never written to disk or executed;
- ZIP files are only *listed* (names, sizes, encryption flag), never extracted.
"""

import io
import re
import zipfile
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

from .domains import address_domain, normalize_host

MAX_MESSAGE_BYTES = 30 * 1024 * 1024   # Gmail's own limit is 25 MB
MAX_ZIP_MEMBERS = 500
MAX_TEXT_CHARS = 200_000               # enough for any real email body

URL_IN_TEXT = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)|font-size\s*:\s*[01]px|max-height\s*:\s*0",
    re.IGNORECASE,
)


class MessageTooLarge(ValueError):
    pass


@dataclass
class Link:
    href: str
    text: str

    @property
    def host(self) -> str:
        try:
            return normalize_host(urlparse(self.href).hostname or "")
        except ValueError:          # malformed URL from an attacker
            return ""

    @property
    def path(self) -> str:
        try:
            return urlparse(self.href).path or ""
        except ValueError:
            return ""


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    archive_members: list = field(default_factory=list)  # names inside a ZIP
    archive_encrypted: bool = False
    archive_unreadable: bool = False


@dataclass
class ParsedEmail:
    headers: EmailMessage
    from_header: str
    from_display_name: str
    from_domain: str
    reply_to_domain: str
    recipient_local_parts: set
    subject: str
    auth_results: str          # the header written by the receiving server only
    visible_text: str
    links: list
    hidden_element_count: int
    attachments: list


class _HtmlExtractor(HTMLParser):
    """Collects visible text, <a href> links and hidden elements.

    Ignores <script>, <style> and comments (spam often hides junk text there).
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text_parts = []
        self.links = []
        self.hidden_count = 0
        self._skip_depth = 0
        self._current_href = None
        self._current_text = []
        # Hidden elements currently open: [tag, already_counted]. We only count
        # hidden elements that contain real words; empty 1px divider lines are
        # just layout, not hidden text.
        self._hidden_stack = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("script", "style", "head", "title"):
            self._skip_depth += 1
        if HIDDEN_STYLE.search(attrs.get("style") or ""):
            self._hidden_stack.append([tag, False])
        if tag == "a" and attrs.get("href"):
            self._current_href = attrs["href"].strip()
            self._current_text = []

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head", "title") and self._skip_depth:
            self._skip_depth -= 1
        if self._hidden_stack and self._hidden_stack[-1][0] == tag:
            self._hidden_stack.pop()
        if tag == "a" and self._current_href is not None:
            text = " ".join("".join(self._current_text).split())
            self.links.append(Link(href=self._current_href, text=text))
            self._current_href = None

    def handle_data(self, data):
        if self._skip_depth:
            return
        if self._hidden_stack and data.replace("\xa0", " ").strip():
            innermost = self._hidden_stack[-1]
            if not innermost[1]:
                innermost[1] = True
                self.hidden_count += 1
        self.text_parts.append(data)
        if self._current_href is not None:
            self._current_text.append(data)


def _trusted_auth_results(msg: EmailMessage, authserv_id: str) -> str:
    """Return the Authentication-Results header added by *our* mail server.

    Anyone can put a fake 'Authentication-Results: ... dkim=pass' header in the
    email they send. Only the one stamped by the receiving server (for Gmail,
    'mx.google.com') can be trusted, and it is the topmost one.
    """
    for value in msg.get_all("Authentication-Results") or []:
        text = " ".join(str(value).split())
        if text.lower().startswith(authserv_id.lower()):
            return text
    return ""


def _inspect_zip(payload: bytes, attachment: Attachment) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for info in archive.infolist()[:MAX_ZIP_MEMBERS]:
                attachment.archive_members.append(info.filename)
                if info.flag_bits & 0x1:
                    attachment.archive_encrypted = True
    except (zipfile.BadZipFile, ValueError, OSError):
        attachment.archive_unreadable = True


def _safe_get_text(part) -> str:
    try:
        return part.get_content()
    except (LookupError, ValueError, AssertionError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def parse_email(raw: bytes, authserv_id: str = "mx.google.com") -> ParsedEmail:
    if len(raw) > MAX_MESSAGE_BYTES:
        raise MessageTooLarge(f"message is larger than {MAX_MESSAGE_BYTES} bytes")

    msg = BytesParser(policy=policy.default).parsebytes(raw)

    from_header = str(msg.get("From", ""))
    display_name, _ = parseaddr(from_header)

    recipients = set()
    for header in ("To", "Delivered-To"):
        for value in msg.get_all(header) or []:
            _, addr = parseaddr(str(value))
            if "@" in addr:
                recipients.add(addr.split("@", 1)[0].lower())

    html_extractor = _HtmlExtractor()
    plain_parts = []
    attachments = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        content_type = part.get_content_type()

        if filename or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachment = Attachment(
                filename=filename or "(unnamed)",
                content_type=content_type,
                size=len(payload),
            )
            if (filename or "").lower().endswith(".zip") or content_type in (
                "application/zip", "application/x-zip-compressed"
            ):
                _inspect_zip(payload, attachment)
            attachments.append(attachment)
        elif content_type == "text/html":
            html_extractor.feed(_safe_get_text(part)[:MAX_TEXT_CHARS])
        elif content_type == "text/plain":
            plain_parts.append(_safe_get_text(part)[:MAX_TEXT_CHARS])

    links = list(html_extractor.links)
    if not links:  # plain-text only email: take URLs written in the text
        for text in plain_parts:
            links.extend(Link(href=url, text="") for url in URL_IN_TEXT.findall(text))

    visible_text = " ".join(" ".join(html_extractor.text_parts + plain_parts).split())

    return ParsedEmail(
        headers=msg,
        from_header=from_header,
        from_display_name=display_name.strip(),
        from_domain=address_domain(from_header),
        reply_to_domain=address_domain(str(msg.get("Reply-To", ""))),
        recipient_local_parts=recipients,
        subject=str(msg.get("Subject", "")),
        auth_results=_trusted_auth_results(msg, authserv_id),
        visible_text=visible_text[:MAX_TEXT_CHARS],
        links=links,
        hidden_element_count=html_extractor.hidden_count,
        attachments=attachments,
    )
