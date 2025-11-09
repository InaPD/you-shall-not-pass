"""`exfiltration` family: intent-defined, not placement-defined (spec 16.2).

These attacks reuse the direct, hidden_text and metadata placements; what groups
them is the payload's goal - getting the agent to send something out that it
should not. The report groups by family, so they need their own module even
though every placement is delegated.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from corpus.attacks.generators import direct, hidden_text, metadata

_DELEGATES = (direct, hidden_text, metadata)
PLACEMENTS = tuple(
    placement for module in _DELEGATES for placement in module.PLACEMENTS
)


def build(
    profile: dict[str, Any],
    payload: str,
    out_dir: Path,
    attack_id: str,
    *,
    placement: str,
) -> Path:
    for module in _DELEGATES:
        if placement in module.PLACEMENTS:
            return module.build(profile, payload, out_dir, attack_id, placement=placement)
    raise ValueError(f"unknown exfiltration placement {placement!r}")
