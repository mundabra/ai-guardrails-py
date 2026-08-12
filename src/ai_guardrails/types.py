"""Core result types.

Python sibling of mundabra/ai-guardrails (TypeScript). Where the TS library
returns verdict-only results (src/types.ts GuardResult), this library is
span-based: every detection carries the matched rule, category, weight and
character offsets, so consumers can annotate, redact, or score precisely.
Verdict parity with the TS library is held by shared test vectors, not by
identical API shapes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Action = Literal["allow", "warn", "block", "redact"]

Stage = Literal["input", "output", "retrieval", "tool_input", "tool_output"]

#: Truncation length for previews carried in findings/reports. Full matched
#: content is never stored on a report — a privacy property consumers can
#: rely on when shipping reports to logs or audit trails.
PREVIEW_MAX_CHARS = 80


def preview(text: str, limit: int = PREVIEW_MAX_CHARS) -> str:
    """Truncated, newline-flattened preview. Never returns the full text for
    inputs longer than ``limit``."""
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def mask(value: str) -> str:
    """Shape-preserving mask for sensitive values.

    Truncation alone is not privacy: a short secret (an SSN, a card number) is
    shorter than any sane preview limit, so it would survive verbatim. Findings
    from the PII and secrets guards use this instead — enough to correlate and
    debug, never enough to use.
    """
    flat = " ".join(value.split())
    if len(flat) <= 6:
        return f"…({len(flat)} chars)"
    return f"{flat[:2]}…{flat[-2:]} ({len(flat)} chars)"


def mask_url(url: str, limit: int = PREVIEW_MAX_CHARS) -> str:
    """Preview a URL with its query string dropped.

    For an exfiltration finding the query string *is* the stolen data — keeping
    it in a report would re-leak precisely what the guard caught leaving.
    """
    base = url.split("?", 1)[0].split("#", 1)[0]
    had_query = len(base) != len(url)
    return preview(base, limit) + ("?…" if had_query else "")


@dataclass(frozen=True)
class Finding:
    """One rule hit. ``span`` is (start, end) in the *original* text when the
    match was located there, or None when the hit only exists in normalized
    text (e.g. a pattern that surfaced after base64 decoding)."""

    guard: str
    category: str
    rule_id: str
    weight: float
    span: tuple[int, int] | None = None
    value_preview: str = ""


@dataclass(frozen=True)
class Verdict:
    """Outcome of one guard over one text."""

    action: Action
    guard: str
    score: float = 0.0
    findings: tuple[Finding, ...] = ()
    reason: str = ""
    code: str = ""
    #: Present only for action == "redact".
    redacted: str | None = None

    @property
    def categories(self) -> tuple[str, ...]:
        seen: dict[str, None] = {}
        for f in self.findings:
            seen.setdefault(f.category, None)
        return tuple(seen)


@dataclass(frozen=True)
class Scan:
    """Aggregate of several guards over one text (see scanner.scan_text)."""

    action: Action
    verdicts: tuple[Verdict, ...] = ()
    normalization_steps: tuple[str, ...] = ()
    #: The text the spans index into — kept so `redacted` can rewrite the whole
    #: document. Never included in a report.
    _source: str | None = None

    @property
    def findings(self) -> tuple[Finding, ...]:
        out: list[Finding] = []
        for v in self.verdicts:
            out.extend(v.findings)
        return tuple(out)

    @property
    def flagged(self) -> bool:
        return self.action in ("warn", "block", "redact")

    @property
    def redacted(self) -> str | None:
        """One rendering with EVERY guard's matches removed, or None if nothing
        matched.

        Individual verdicts each redact the original text, so they are mutually
        exclusive — a caller that reads one of them keeps whatever the other
        found. This merges the spans and applies them once.
        """
        from .redact import apply_redactions

        spans = [f.span for f in self.findings if f.span]
        if not spans or self._source is None:
            return None
        # A single placeholder for both kinds: the distinction is in the
        # findings, and interleaving two markers over merged spans would be a
        # lie about which one covered an overlap.
        return apply_redactions(self._source, spans, "[REDACTED]")


_ACTION_RANK: dict[str, int] = {"allow": 0, "warn": 1, "redact": 2, "block": 3}


def worst_action(actions: list[Action] | tuple[Action, ...]) -> Action:
    """The most severe of the given actions ("allow" when empty)."""
    if not actions:
        return "allow"
    return max(actions, key=lambda a: _ACTION_RANK[a])


@dataclass(frozen=True)
class ScanReport:
    """Serializable, privacy-clean summary of a Scan — designed to drop into
    audit/event pipelines. Carries rule ids, categories and truncated previews
    only; never full content."""

    action: Action
    guards: tuple[str, ...]
    categories: tuple[str, ...]
    finding_count: int
    content_hash: str
    content_length: int
    previews: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "guards": list(self.guards),
            "categories": list(self.categories),
            "finding_count": self.finding_count,
            "content_hash": self.content_hash,
            "content_length": self.content_length,
            "previews": list(self.previews),
        }
