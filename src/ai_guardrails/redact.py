"""Span-splicing shared by every redacting guard.

Guards find spans; this turns spans into a rewritten string. Two rules the
naive version got wrong, both of which produce output a caller would wrongly
believe is safe to show:

- **Overlapping spans must merge.** The PII patterns genuinely overlap (an email
  regex and a phone regex both match inside ``555-123-4567@example.com``).
  Splicing them independently makes the second splice index into the string the
  first one already rewrote, deleting text that was never sensitive.
- **Text past the scan bound must survive.** Scanning is bounded for cost, but
  redaction rewrites the *document*. Returning only the scanned prefix silently
  discards the rest.
"""

from __future__ import annotations

from collections.abc import Iterable


def merge_spans(spans: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    """Sorted, non-overlapping spans covering the same characters."""
    ordered = sorted((s, e) for s, e in spans if e > s)
    merged: list[tuple[int, int]] = []
    for start, end in ordered:
        if merged and start <= merged[-1][1]:
            prev_start, prev_end = merged[-1]
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))
    return merged


def apply_redactions(
    text: str,
    spans: Iterable[tuple[int, int]],
    replacement: str,
) -> str:
    """Replace every (merged) span in ``text``.

    ``text`` is the FULL document even when the spans came from a bounded scan —
    offsets are valid because bounding only ever truncates the tail.
    """
    out = text
    for start, end in reversed(merge_spans(spans)):
        out = out[:start] + replacement + out[end:]
    return out
