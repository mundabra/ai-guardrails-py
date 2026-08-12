"""Load pattern corpora from packaged JSON.

Corpus-as-data (vs the TS library's inline arrays): patterns/weights/categories
live in ``data/*.json`` so the same corpus can be shared across languages and
updated without code changes. Compiled once at import.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import cache
from importlib import resources


@dataclass(frozen=True)
class WeightedPattern:
    category: str
    weight: float
    regex: re.Pattern[str]
    rule_id: str


@dataclass(frozen=True)
class Corpus:
    patterns: tuple[WeightedPattern, ...]
    block_threshold: float
    warn_ratio: float
    was_normalized_bonus: float
    multi_category_min: int
    multi_category_bonus: float


def _load_json(name: str) -> dict:
    with resources.files("ai_guardrails.data").joinpath(name).open(encoding="utf-8") as f:
        return json.load(f)


@cache
def load_corpus(name: str) -> Corpus:
    """Load and compile a corpus JSON by filename (e.g. ``injection.json``).

    Every pattern compiles case-insensitively to mirror the TS library's ``/i``
    flag; inline flags in the source (e.g. ``(?m)``) still apply.
    """
    raw = _load_json(name)
    defaults = raw.get("defaults", {})
    bonuses = raw.get("bonuses", {})
    patterns: list[WeightedPattern] = []
    counts: dict[str, int] = {}
    for entry in raw["patterns"]:
        cat = entry["category"]
        counts[cat] = counts.get(cat, 0) + 1
        patterns.append(
            WeightedPattern(
                category=cat,
                weight=float(entry["weight"]),
                regex=re.compile(entry["re"], re.IGNORECASE),
                rule_id=f"{cat}.{counts[cat]}",
            )
        )
    return Corpus(
        patterns=tuple(patterns),
        block_threshold=float(defaults.get("block_threshold", 0.7)),
        warn_ratio=float(defaults.get("warn_ratio", 0.5)),
        was_normalized_bonus=float(bonuses.get("was_normalized", 0.0)),
        multi_category_min=int(bonuses.get("multi_category_min", 3)),
        multi_category_bonus=float(bonuses.get("multi_category", 0.0)),
    )
