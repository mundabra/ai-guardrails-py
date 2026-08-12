"""Redaction has to remove every match and damage nothing else.

A redactor that misses the second secret, or that eats the characters after an
overlapping match, is worse than no redactor: the caller believes the string is
safe to show.
"""

from __future__ import annotations

from ai_guardrails import scan_output
from ai_guardrails.guards import scan_pii, scan_secrets


def test_every_secret_of_a_type_is_redacted_not_just_the_first():
    text = "a AKIAIOSFODNN7EXAMPLE b AKIAJ7XYZABCDEFGHIJK"
    out = scan_secrets(text, action="redact").redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "AKIAJ7XYZABCDEFGHIJK" not in out


def test_overlapping_pii_matches_do_not_eat_surrounding_text():
    # EMAIL_RE and PHONE_RE both match inside "555-123-4567@example.com".
    out = scan_pii("Contact 555-123-4567@example.com now please", action="redact").redacted
    assert out.startswith("Contact ")
    assert out.endswith(" now please"), out


def test_redaction_preserves_content_past_the_scan_bound():
    """Scanning is bounded for cost; redaction must never truncate the document."""
    tail = "x" * 5000
    text = "key AKIAIOSFODNN7EXAMPLE " + tail
    v = scan_secrets(text, action="redact", max_chars=100)
    assert v.redacted.endswith(tail)
    assert "AKIAIOSFODNN7EXAMPLE" not in v.redacted


def test_scan_redacted_merges_every_guard():
    """The single accessor a caller should use: one string with secrets AND PII
    removed, rather than two mutually exclusive renderings."""
    text = "key AKIAIOSFODNN7EXAMPLE for sarah@acme.example, SSN 536-90-4399"
    scan = scan_output(text, redact=True)
    out = scan.redacted
    assert out is not None
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "sarah@acme.example" not in out
    assert "536-90-4399" not in out
    assert "key " in out and " for " in out  # surrounding prose intact


def test_scan_redacted_is_none_when_nothing_matched():
    assert scan_output("nothing sensitive here", redact=True).redacted is None


def test_unknown_action_is_rejected_rather_than_silently_flipped():
    import pytest

    with pytest.raises(ValueError):
        scan_pii("a@b.example", action="warn")
    with pytest.raises(ValueError):
        scan_secrets("AKIAIOSFODNN7EXAMPLE", action="warn")
