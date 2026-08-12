"""Data-exfiltration detection via markdown/HTML image & link injection.

Port of mundabra/ai-guardrails src/guards/output/exfiltration.ts.
"""

from __future__ import annotations

import re

from ..patterns import HTML_IMG_RE, MARKDOWN_IMAGE_RE, MARKDOWN_LINK_RE
from ..types import Finding, Verdict, mask_url

_SUSPICIOUS = [
    re.compile(r"\?[^)]{100,}"),
    re.compile(r"[?&][^=]+=(?:[A-Za-z0-9+/]{30,})"),
    re.compile(r"[?&][^=]+=(?:[0-9a-fA-F]{30,})"),
    re.compile(
        r"(?:webhook\.site|requestbin|pipedream|hookbin|burpcollaborator|interact\.sh)",
        re.IGNORECASE,
    ),
]


def _suspicious(url: str) -> bool:
    return any(p.search(url) for p in _SUSPICIOUS)


def scan_exfiltration(content: str) -> Verdict:
    checks = (
        (MARKDOWN_IMAGE_RE, 2, "exfiltration_image", "markdown image"),
        (MARKDOWN_LINK_RE, 2, "exfiltration_link", "markdown link"),
        (HTML_IMG_RE, 1, "exfiltration_html", "HTML image"),
    )
    for rex, group, code, label in checks:
        for m in rex.finditer(content):
            url = m.group(group)
            if _suspicious(url):
                safe_url = mask_url(url)
                finding = Finding(
                    guard="exfiltration",
                    category="exfiltration",
                    rule_id=code,
                    weight=1.0,
                    span=(m.start(), m.end()),
                    value_preview=safe_url,
                )
                return Verdict(
                    action="block",
                    guard="exfiltration",
                    findings=(finding,),
                    # The query string is the payload being exfiltrated — the
                    # reason must not carry it either (reasons reach logs).
                    reason=f"Data exfiltration attempt via {label}: {safe_url}",
                    code=code,
                )
    return Verdict(action="allow", guard="exfiltration")
