"""Shared regex patterns.

Port of mundabra/ai-guardrails src/utils/patterns.ts. Kept as a flat module so
both the output guards and any consumer can reuse them.
"""

from __future__ import annotations

import re

# PII
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CREDIT_CARD_RE = re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")
CREDIT_CARD_AMEX_RE = re.compile(r"\b\d{4}[\s-]?\d{6}[\s-]?\d{5}\b")
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b")
IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

# Secrets
AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GITHUB_PAT_RE = re.compile(r"\bghp_[0-9a-zA-Z]{36}\b")
GITHUB_OAUTH_RE = re.compile(r"\bgho_[0-9a-zA-Z]{36}\b")
GITHUB_APP_RE = re.compile(r"\bghs_[0-9a-zA-Z]{36}\b")
GITHUB_FINE_RE = re.compile(r"\bgithub_pat_[0-9a-zA-Z_]{82}\b")
GOOGLE_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
STRIPE_SECRET_RE = re.compile(r"\bsk_(?:live|test)_[0-9a-zA-Z]{24,}\b")
STRIPE_PUBLISHABLE_RE = re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b")
SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[0-9a-zA-Z-]{10,}\b")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
SSH_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----")
GENERIC_SECRET_RE = re.compile(
    r"(?:secret|password|token|key|apikey|api_key)[\s]*[=:]\s*[\"']?([^\s\"']{16,})[\"']?",
    re.IGNORECASE,
)

# Exfiltration
MARKDOWN_IMAGE_RE = re.compile(r"!\[([^\]]*)\]\((https?://[^)]+)\)")
MARKDOWN_LINK_RE = re.compile(r"\[([^\]]*)\]\((https?://[^)]+)\)")
HTML_IMG_RE = re.compile(r"<img[^>]+src=[\"'](https?://[^\"']+)[\"'][^>]*>", re.IGNORECASE)
