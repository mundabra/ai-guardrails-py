"""Luhn checksum — port of mundabra/ai-guardrails src/utils/luhn.ts."""

from __future__ import annotations


def luhn_check(num: str) -> bool:
    digits = [c for c in num if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    alternate = False
    for c in reversed(digits):
        n = int(c)
        if alternate:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alternate = not alternate
    return total % 10 == 0
