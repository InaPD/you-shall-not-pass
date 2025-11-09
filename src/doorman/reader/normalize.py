"""Map extracted skills onto a closed vocabulary (spec 9).

Case-insensitive exact match first, then the alias table. Unknown skills are
dropped rather than kept, and the count is logged so a resume that loses most of
its skills is visible in the trace.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from doorman.config import CONFIG_DIR

TAXONOMY_PATH = CONFIG_DIR / "skills_taxonomy.yaml"


@lru_cache(maxsize=1)
def _lookup(path: str | None = None) -> dict[str, str]:
    """lowercased name or alias -> canonical name."""
    source = Path(path) if path else TAXONOMY_PATH
    data = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    table: dict[str, str] = {}
    for canonical, aliases in (data.get("canonical") or {}).items():
        table[canonical.lower()] = canonical
        for alias in aliases or []:
            table[str(alias).lower()] = canonical
    return table


def canonical_skills() -> set[str]:
    return set(_lookup().values())


def normalize_skills(skills: list[str]) -> tuple[list[str], int]:
    """Return (canonical skills in first-seen order, number dropped)."""
    table = _lookup()
    kept: list[str] = []
    dropped = 0
    for raw in skills:
        canonical = table.get(str(raw).strip().lower())
        if canonical is None:
            dropped += 1
        elif canonical not in kept:
            kept.append(canonical)
    return kept, dropped
