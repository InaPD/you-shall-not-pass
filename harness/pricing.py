"""Token counts -> dollars, from config/pricing.yaml (spec 18).

Prices live in configuration, never in code, because they change and a stale
constant compiled into the harness would silently mis-report the cost of a run
that has already happened. A model with no price recorded yields `None` rather
than zero: an unknown cost and a free run are different facts, and a report that
conflates them understates the bill.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from doorman.config import CONFIG_DIR

PRICING_PATH = CONFIG_DIR / "pricing.yaml"
PER_TOKENS = 1_000_000


@lru_cache(maxsize=4)
def load(path: Path | None = None) -> dict[str, dict[str, float | None]]:
    source = Path(path) if path else PRICING_PATH
    if not source.is_file():
        return {}
    return yaml.safe_load(source.read_text(encoding="utf-8")) or {}


def rate(model: str, path: Path | None = None) -> tuple[float, float] | None:
    """(input, output) USD per million tokens, or None if either is unpriced."""
    entry = load(path).get(model) or {}
    in_rate, out_rate = entry.get("input"), entry.get("output")
    if in_rate is None or out_rate is None:
        return None
    return float(in_rate), float(out_rate)


def cost_usd(
    model: str, input_tokens: int, output_tokens: int, path: Path | None = None
) -> float | None:
    rates = rate(model, path)
    if rates is None:
        return None
    in_rate, out_rate = rates
    return round((input_tokens * in_rate + output_tokens * out_rate) / PER_TOKENS, 6)

