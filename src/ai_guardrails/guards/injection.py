"""Prompt-injection scoring guard.

Port of mundabra/ai-guardrails src/guards/input/injection.ts. Weighted patterns
run over normalized text; scores accumulate with a normalization signal and a
multi-category bonus; block/warn thresholds mirror the TS defaults. Findings
are span-less because matches live in normalized space, not the original text.
"""

from __future__ import annotations

import re

from ..corpus import load_corpus
from ..normalize import normalize
from ..types import Finding, Verdict


def scan_injection(
    content: str,
    *,
    threshold: float | None = None,
    allowlist: tuple[str, ...] = (),
    extra_patterns: tuple[tuple[str, float], ...] = (),
) -> Verdict:
    corpus = load_corpus("injection.json")
    block_threshold = corpus.block_threshold if threshold is None else threshold

    lower_content = content.lower()
    if any(phrase.lower() in lower_content for phrase in allowlist):
        return Verdict(action="allow", guard="injection")

    result = normalize(content)
    # Match against BOTH the normalized text and the raw text, taking the union
    # of rule hits (each rule scores at most once).
    #
    # Normalization is not loss-free: step 9 collapses repeated characters, so
    # "### SYSTEM" becomes "# SYSTEM" and the delimiter-abuse patterns (`#{3,}`,
    # `={3,}`, `-{3,}`) can never fire on normalized text. Scanning raw as well
    # closes that hole — an attacker can hide neither by obfuscating (raw misses,
    # normalized catches) nor by staying plain (normalized misses, raw catches).
    haystacks = (result.text, content) if content != result.text else (result.text,)

    score = 0.0
    findings: list[Finding] = []
    categories: dict[str, None] = {}
    for wp in corpus.patterns:
        if any(wp.regex.search(h) for h in haystacks):
            score += wp.weight
            categories.setdefault(wp.category, None)
            findings.append(
                Finding(
                    guard="injection",
                    category=wp.category,
                    rule_id=wp.rule_id,
                    weight=wp.weight,
                )
            )

    for pat, weight in extra_patterns:
        if any(re.search(pat, h, re.IGNORECASE) for h in haystacks):
            score += weight
            categories.setdefault("custom", None)
            findings.append(
                Finding(guard="injection", category="custom", rule_id="custom", weight=weight)
            )

    if result.was_normalized:
        score += corpus.was_normalized_bonus
    if len(categories) >= corpus.multi_category_min:
        score += corpus.multi_category_bonus

    cats = ", ".join(categories)
    if score >= block_threshold:
        action = "block"
        code = "prompt_injection"
        reason = f"Prompt injection detected (score: {score:.2f}, categories: {cats})"
    elif score >= block_threshold * corpus.warn_ratio:
        action = "warn"
        code = "prompt_injection_warning"
        reason = f"Possible prompt injection (score: {score:.2f}, categories: {cats})"
    else:
        return Verdict(action="allow", guard="injection", score=score)

    return Verdict(
        action=action,
        guard="injection",
        score=score,
        findings=tuple(findings),
        reason=reason,
        code=code,
    )
