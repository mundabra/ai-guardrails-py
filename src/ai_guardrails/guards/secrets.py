"""Secret/API-key detection.

Port of mundabra/ai-guardrails src/guards/output/secrets.ts, with an FP-
reduction improvement: the generic high-entropy pattern additionally requires a
nearby assignment keyword (already in the regex) AND Shannon entropy >= 4.0
AND (new) rejects values that are all one character class / dictionary-ish.
"""

from __future__ import annotations

import math

from ..patterns import (
    AWS_ACCESS_KEY_RE,
    GENERIC_SECRET_RE,
    GITHUB_APP_RE,
    GITHUB_FINE_RE,
    GITHUB_OAUTH_RE,
    GITHUB_PAT_RE,
    GOOGLE_API_KEY_RE,
    JWT_RE,
    SLACK_TOKEN_RE,
    SSH_PRIVATE_KEY_RE,
    STRIPE_SECRET_RE,
)
from ..types import Finding, Verdict, mask

_ALL_TYPES = (
    "aws",
    "github",
    "google",
    "stripe",
    "slack",
    "jwt",
    "ssh_key",
    "generic_high_entropy",
)

_SECRET_PATTERNS = [
    ("aws", [AWS_ACCESS_KEY_RE]),
    ("github", [GITHUB_PAT_RE, GITHUB_OAUTH_RE, GITHUB_APP_RE, GITHUB_FINE_RE]),
    ("google", [GOOGLE_API_KEY_RE]),
    ("stripe", [STRIPE_SECRET_RE]),
    ("slack", [SLACK_TOKEN_RE]),
    ("jwt", [JWT_RE]),
    ("ssh_key", [SSH_PRIVATE_KEY_RE]),
    ("generic_high_entropy", [GENERIC_SECRET_RE]),
]

_SAFE_PUBLIC_TOKEN_PREFIXES = ("pk_live_", "pk_test_")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _generic_is_secret(value: str) -> bool:
    if value.startswith(_SAFE_PUBLIC_TOKEN_PREFIXES):
        return False
    if shannon_entropy(value) < 4.0:
        return False
    # Improvement over TS: reject values with no digit AND no case mix — those
    # are almost always ordinary words/phrases, not tokens.
    has_digit = any(c.isdigit() for c in value)
    has_mixed_case = any(c.islower() for c in value) and any(c.isupper() for c in value)
    return has_digit or has_mixed_case


def scan_secrets(
    content: str,
    *,
    types: tuple[str, ...] = _ALL_TYPES,
    action: str = "block",
) -> Verdict:
    findings: list[Finding] = []
    seen_types: dict[str, None] = {}

    for kind, patterns in _SECRET_PATTERNS:
        if kind not in types:
            continue
        for rex in patterns:
            for m in rex.finditer(content):
                if kind == "generic_high_entropy":
                    value = m.group(1) if m.lastindex else m.group(0)
                    if not _generic_is_secret(value):
                        continue
                seen_types.setdefault(kind, None)
                findings.append(
                    Finding(
                        guard="secrets",
                        category=kind,
                        rule_id=kind,
                        weight=1.0,
                        span=(m.start(), m.end()),
                        value_preview=mask(m.group(0)),
                    )
                )
                break  # one match per pattern is enough to flag the type

    if not findings:
        return Verdict(action="allow", guard="secrets")

    kinds = ", ".join(seen_types)
    if action == "redact":
        redacted = content
        for f in sorted(findings, key=lambda x: x.span[0], reverse=True):  # type: ignore[index]
            start, end = f.span  # type: ignore[misc]
            redacted = redacted[:start] + "[SECRET_REDACTED]" + redacted[end:]
        return Verdict(
            action="redact",
            guard="secrets",
            findings=tuple(findings),
            reason=f"Secrets redacted: {kinds}",
            code="secret_redacted",
            redacted=redacted,
        )
    return Verdict(
        action="block",
        guard="secrets",
        findings=tuple(findings),
        reason=f"Secrets detected: {kinds}",
        code="secret_detected",
    )
