"""PII detection + redaction.

Port of mundabra/ai-guardrails src/guards/output/pii.ts. Findings carry spans
in the original text (these guards run on un-normalized content), enabling
precise redaction.
"""

from __future__ import annotations

from ..luhn import luhn_check
from ..patterns import (
    CREDIT_CARD_AMEX_RE,
    CREDIT_CARD_RE,
    EMAIL_RE,
    IPV4_RE,
    PHONE_RE,
    SSN_RE,
)
from ..types import Finding, Verdict, mask

_ALL_TYPES = ("ssn", "credit_card", "email", "phone", "ip")


def _valid_ssn(ssn: str) -> bool:
    d = [c for c in ssn if c.isdigit()]
    area, group, serial = int("".join(d[:3])), int("".join(d[3:5])), int("".join(d[5:]))
    if area in (0, 666) or area >= 900:
        return False
    return group != 0 and serial != 0


def _valid_email(email: str) -> bool:
    local = email.split("@", 1)[0]
    if not local or local.startswith(".") or local.endswith("."):
        return False
    return ".." not in local


def _valid_ipv4(ip: str) -> bool:
    return all(0 <= int(o) <= 255 for o in ip.split("."))


def _find(content: str, types: tuple[str, ...], allowlist: tuple[str, ...]) -> list[Finding]:
    out: list[Finding] = []

    def add(kind: str, m) -> None:
        if m.group(0) in allowlist:
            return
        out.append(
            Finding(
                guard="pii",
                category=kind,
                rule_id=kind,
                weight=1.0,
                span=(m.start(), m.end()),
                value_preview=mask(m.group(0)),
            )
        )

    if "ssn" in types:
        for m in SSN_RE.finditer(content):
            if _valid_ssn(m.group(0)):
                add("ssn", m)
    if "credit_card" in types:
        for rex in (CREDIT_CARD_RE, CREDIT_CARD_AMEX_RE):
            for m in rex.finditer(content):
                if luhn_check(m.group(0)):
                    add("credit_card", m)
    if "email" in types:
        for m in EMAIL_RE.finditer(content):
            if _valid_email(m.group(0)):
                add("email", m)
    if "phone" in types:
        for m in PHONE_RE.finditer(content):
            if sum(c.isdigit() for c in m.group(0)) >= 10:
                add("phone", m)
    if "ip" in types:
        for m in IPV4_RE.finditer(content):
            if _valid_ipv4(m.group(0)):
                add("ip", m)
    return out


def scan_pii(
    content: str,
    *,
    types: tuple[str, ...] = _ALL_TYPES,
    action: str = "redact",
    redact_with: str = "[REDACTED]",
    allowlist: tuple[str, ...] = (),
) -> Verdict:
    findings = _find(content, types, allowlist)
    if not findings:
        return Verdict(action="allow", guard="pii")

    kinds = ", ".join(dict.fromkeys(f.category for f in findings))
    n = len(findings)
    plural = "s" if n > 1 else ""

    if action == "block":
        return Verdict(
            action="block",
            guard="pii",
            findings=tuple(findings),
            reason=f"PII detected: {kinds} ({n} instance{plural})",
            code="pii_detected",
        )

    redacted = content
    for f in sorted(findings, key=lambda x: x.span[0], reverse=True):  # type: ignore[index]
        start, end = f.span  # type: ignore[misc]
        redacted = redacted[:start] + redact_with + redacted[end:]
    return Verdict(
        action="redact",
        guard="pii",
        findings=tuple(findings),
        reason=f"PII redacted: {kinds} ({n} instance{plural})",
        code="pii_redacted",
        redacted=redacted,
    )
