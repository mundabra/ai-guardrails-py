"""Input normalization pipeline.

Port of mundabra/ai-guardrails src/utils/normalize.ts (13 steps), plus one
Python-only step: Unicode tag-character decoding. Encoding bypasses defeat
naive pattern matching; this pipeline decodes, deobfuscates and normalizes
text before guards inspect it. Step names match the TS implementation so
cross-language fixtures stay diffable.

Note: this pipeline is deliberately lossy (it collapses repeated characters),
so callers that match structural/delimiter patterns must also scan the raw
text — see guards/injection.py.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

# Zero-width and invisible Unicode characters (normalize.ts ZERO_WIDTH_RE)
_ZERO_WIDTH_RE = re.compile(
    "[\u200B\u200C\u200D\u200E\u200F\uFEFF\u00AD\u2060\u2061\u2062\u2063\u2064\u180E]"
)

# Invisible formatting: RTL override, bidi marks, etc. (INVISIBLE_FORMAT_RE)
_INVISIBLE_FORMAT_RE = re.compile(
    "[\u202A-\u202E\u2066-\u2069\u061C\u00AD\u034F\u115F\u1160\u17B4\u17B5\uFFA0]"
)

# Unicode tag characters (U+E0000-E007F). Not in the TS sibling: these are an
# invisible instruction-smuggling channel — every ASCII character has a tag
# twin that renders as nothing but survives tokenization. Mapped back to their
# ASCII equivalents (rather than dropped) so smuggled text becomes visible to
# the pattern guards instead of silently vanishing.
_TAG_CHAR_RE = re.compile(r"[\U000E0000-\U000E007F]")

# HTML entities: named + numeric + hex (HTML_ENTITY_RE)
_HTML_ENTITY_RE = re.compile(r"&(#x?[\da-fA-F]+|#\d+|[a-zA-Z]+);")

# Base64 segment: >=24 chars of valid charset with proper padding (BASE64_RE)
_BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

_HEX_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){3,}")
_HEX_BYTE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")

_URL_ENCODED_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")

_LEET_MAP = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "!": "i", "$": "s"}
)
_LEET_CHARS_RE = re.compile(r"[013457@!$]")

_REPEATED_CHAR_RE = re.compile(r"(.)\1{2,}")

_WHITESPACE_RE = re.compile(r"\s+")

_PRINTABLE_RE = re.compile(r"^[\x20-\x7E\n\r\t]+$")

_SINGLE_CHAR_WORD_RE = re.compile(r"\b[a-zA-Z]\b")
_DEFRAG_RE = re.compile(r"\b([a-zA-Z])\s+(?=[a-zA-Z]\b)")

_HTML_ENTITY_MAP = {"lt": "<", "gt": ">", "amp": "&", "quot": '"', "apos": "'", "nbsp": " "}

# ROT13 gate: only decode when it reveals injection keywords absent from the
# raw text (normalize.ts step 7 — avoids false positives on normal prose).
_INJECTION_KEYWORDS = ("ignore", "instruction", "system", "override", "admin")


@dataclass(frozen=True)
class NormalizeResult:
    text: str
    was_normalized: bool
    steps: tuple[str, ...]


def _decode_entity(m: re.Match[str]) -> str:
    entity = m.group(1)
    try:
        if entity.startswith(("#x", "#X")):
            return chr(int(entity[2:], 16))
        if entity.startswith("#"):
            return chr(int(entity[1:], 10))
    except (ValueError, OverflowError):
        return m.group(0)
    return _HTML_ENTITY_MAP.get(entity.lower(), m.group(0))


def _decode_base64(m: re.Match[str]) -> str:
    raw = m.group(0)
    # Python requires correct padding where JS Buffer tolerates its absence.
    padded = raw + "=" * (-len(raw) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return raw
    # Only replace when the decoded text looks like readable text.
    if len(decoded) >= 4 and _PRINTABLE_RE.match(decoded):
        return decoded
    return raw


def _decode_hex(m: re.Match[str]) -> str:
    return _HEX_BYTE_RE.sub(lambda b: chr(int(b.group(1), 16)), m.group(0))


def _untag(m: re.Match[str]) -> str:
    """U+E0020-U+E007E map to ASCII 0x20-0x7E; the rest (tag begin/cancel) drop."""
    cp = ord(m.group(0))
    return chr(cp - 0xE0000) if 0xE0020 <= cp <= 0xE007E else ""


def normalize(text: str) -> NormalizeResult:
    """Run the full pipeline. ``was_normalized`` is True when anything beyond
    lowercasing fired — itself a signal guards may score."""
    steps: list[str] = []

    def apply(step: str, new_text: str) -> None:
        nonlocal text
        if new_text != text:
            steps.append(step)
            text = new_text

    # 0 (Python-only): decode Unicode tag characters back to ASCII
    apply("invisible_tags", _TAG_CHAR_RE.sub(_untag, text))
    # 1: strip zero-width characters
    apply("zero_width", _ZERO_WIDTH_RE.sub("", text))
    # 2: Unicode NFKC (collapses homoglyphs)
    apply("unicode_nfkc", unicodedata.normalize("NFKC", text))
    # 3: HTML entities
    apply("html_entities", _HTML_ENTITY_RE.sub(_decode_entity, text))
    # 4: base64 segments
    apply("base64", _BASE64_RE.sub(_decode_base64, text))
    # 5: \xNN hex sequences
    apply("hex", _HEX_RE.sub(_decode_hex, text))
    # 6: URL-encoded sequences
    apply("url_encoded", _URL_ENCODED_RE.sub(lambda m: unquote(m.group(0)), text))
    # 7: ROT13, gated on revealing injection keywords not present in the raw text
    rot13 = codecs.decode(text, "rot13")
    lower, rot_lower = text.lower(), rot13.lower()
    if any(kw in rot_lower for kw in _INJECTION_KEYWORDS) and not any(
        kw in lower for kw in _INJECTION_KEYWORDS
    ):
        steps.append("rot13")
        text = rot13
    # 8: collapse whitespace
    apply("whitespace", _WHITESPACE_RE.sub(" ", text).strip())
    # 9: collapse repeated characters (3+ -> 1)
    apply("repeated_chars", _REPEATED_CHAR_RE.sub(r"\1", text))
    # 10: leetspeak — only counts when it changed 3+ characters
    after_leet = text.translate(_LEET_MAP)
    if sum(1 for a, b in zip(text, after_leet, strict=True) if a != b) >= 3:
        steps.append("leetspeak")
        text = after_leet
    # 11: invisible formatting characters
    apply("invisible_format", _INVISIBLE_FORMAT_RE.sub("", text))
    # 12: defragment split tokens ("i g n o r e" -> "ignore"), gated on 4+
    # single-char fragments
    if len(_SINGLE_CHAR_WORD_RE.findall(text)) >= 4:
        apply("defragment", _DEFRAG_RE.sub(r"\1", text))
    # 13: lowercase for comparison
    apply("lowercase", text.lower())

    return NormalizeResult(
        text=text,
        was_normalized=len(steps) > 1,  # lowercase alone doesn't count
        steps=tuple(steps),
    )
