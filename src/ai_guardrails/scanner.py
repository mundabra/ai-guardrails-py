"""High-level scanning API.

Composes the individual guards into stage-oriented entry points and adds the
consumer-driven surface the TS sibling lacks:

- ``scan_tool_result`` — first-class agentic surface (untrusted connector/tool
  output), the common case for indirect prompt injection.
- ``CachedScanner`` — content-hash verdict cache, because agentic consumers
  re-scan a growing history every model call.
- ``ScanReport`` serialization — privacy-clean (rule ids + truncated previews,
  never full content) so verdicts can drop straight into audit/event pipelines.
- Size bounding — large payloads (web fetches) scan a bounded prefix.
"""

from __future__ import annotations

import hashlib
import logging
from collections import OrderedDict

from .guards.exfiltration import scan_exfiltration
from .guards.injection import scan_injection
from .guards.pii import scan_pii
from .guards.secrets import scan_secrets
from .types import Action, Scan, ScanReport, Verdict, preview, worst_action

log = logging.getLogger(__name__)

#: Default cap on characters scanned per call. Guards run over a prefix this
#: long; the tail is still delivered to the model, just not pattern-scanned.
DEFAULT_MAX_SCAN_CHARS = 100_000


def _bounded(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit]


def _safe(guard_name: str, fn, *args, **kwargs) -> Verdict:
    """Run a guard fail-open.

    Consumers call these on every model turn; a guard that raises would break
    their product for the sake of a check. Any failure degrades to "allow" plus
    a logged exception — the same direction metering and policy layers take.
    """
    try:
        return fn(*args, **kwargs)
    except Exception:  # noqa: BLE001 — a guard must never break the caller
        log.exception("guard %s failed (content allowed)", guard_name)
        return Verdict(action="allow", guard=guard_name, code="guard_error")


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def scan_input(text: str, *, max_chars: int = DEFAULT_MAX_SCAN_CHARS) -> Scan:
    """User-authored input: injection scoring only."""
    body = _bounded(text, max_chars)
    v = _safe("injection", scan_injection, body)
    return Scan(action=v.action, verdicts=(v,))


def scan_tool_result(
    source: str,
    text: str,
    *,
    max_chars: int = DEFAULT_MAX_SCAN_CHARS,
) -> Scan:
    """Untrusted tool/connector output. Runs injection scoring plus exfil/secret
    checks — the payload may both *carry* an injection and *be* an exfil vector.
    ``source`` is carried for the consumer's annotation, not used for scoring.
    """
    body = _bounded(text, max_chars)
    verdicts = (
        _safe("injection", scan_injection, body),
        _safe("exfiltration", scan_exfiltration, body),
        _safe("secrets", scan_secrets, body, action="block"),
    )
    action = worst_action([v.action for v in verdicts])
    return Scan(action=action, verdicts=verdicts)


def scan_output(
    text: str,
    *,
    max_chars: int = DEFAULT_MAX_SCAN_CHARS,
    redact: bool = False,
) -> Scan:
    """Model output: secrets, PII, exfiltration. Log-only by default; set
    ``redact`` to have PII/secret verdicts carry a redacted rendering."""
    body = _bounded(text, max_chars)
    verdicts = (
        _safe("secrets", scan_secrets, body, action="redact" if redact else "block"),
        _safe("pii", scan_pii, body, action="redact" if redact else "block"),
        _safe("exfiltration", scan_exfiltration, body),
    )
    action = worst_action([v.action for v in verdicts])
    return Scan(action=action, verdicts=verdicts)


def report(scan: Scan, source_text: str) -> ScanReport:
    """Privacy-clean, serializable summary. Carries no full content."""
    findings = scan.findings
    cats: dict[str, None] = {}
    guards: dict[str, None] = {}
    previews: list[str] = []
    for f in findings:
        cats.setdefault(f.category, None)
        guards.setdefault(f.guard, None)
        if f.value_preview:
            previews.append(f.value_preview)
    return ScanReport(
        action=scan.action,
        guards=tuple(guards),
        categories=tuple(cats),
        finding_count=len(findings),
        content_hash=content_hash(source_text),
        content_length=len(source_text),
        previews=tuple(previews[:8]),
    )


class CachedScanner:
    """LRU verdict cache keyed by (kind, content-hash). One instance per session
    keeps per-call re-scans of an ever-growing history cheap."""

    def __init__(self, capacity: int = 512, *, max_chars: int = DEFAULT_MAX_SCAN_CHARS) -> None:
        self._cap = capacity
        self._max_chars = max_chars
        self._cache: OrderedDict[str, Scan] = OrderedDict()

    def _memo(self, key: str, compute) -> Scan:
        hit = self._cache.get(key)
        if hit is not None:
            self._cache.move_to_end(key)
            return hit
        value = compute()
        self._cache[key] = value
        self._cache.move_to_end(key)
        if len(self._cache) > self._cap:
            self._cache.popitem(last=False)
        return value

    def input(self, text: str) -> Scan:
        return self._memo(
            "in:" + content_hash(text),
            lambda: scan_input(text, max_chars=self._max_chars),
        )

    def tool_result(self, source: str, text: str) -> Scan:
        return self._memo(
            "tool:" + content_hash(text),
            lambda: scan_tool_result(source, text, max_chars=self._max_chars),
        )

    def output(self, text: str, *, redact: bool = False) -> Scan:
        return self._memo(
            f"out{int(redact)}:" + content_hash(text),
            lambda: scan_output(text, max_chars=self._max_chars, redact=redact),
        )


__all__ = [
    "Action",
    "Scan",
    "ScanReport",
    "Verdict",
    "CachedScanner",
    "content_hash",
    "preview",
    "report",
    "scan_input",
    "scan_output",
    "scan_tool_result",
]
