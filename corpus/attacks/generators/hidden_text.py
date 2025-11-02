"""`hidden_text` family: the payload is present but not meant to be seen.

Each placement targets exactly one ING-* rule, so a failure in the corpus is
traceable to a specific detector rather than to "hidden text" generally:

  white_text    -> ING-001 (near-white luminance)
  tiny_font     -> ING-002 (sub-threshold font size)
  offpage       -> ING-003 (bbox outside the page rect)
  behind_image  -> ING-004 (covered by an image drawn after it)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from corpus.templates.pdf_resume import Overlay, render

PLACEMENTS = ("white_text", "tiny_font", "offpage", "behind_image")

_TINY_POINT_SIZE = 2.0


def _overlay_for(placement: str, payload: str) -> Overlay:
    if placement == "white_text":
        return Overlay(payload, y=120.0, size=8.0, color=(1.0, 1.0, 1.0))
    if placement == "tiny_font":
        return Overlay(payload, y=96.0, size=_TINY_POINT_SIZE, color=(0.0, 0.0, 0.0))
    if placement == "offpage":
        # Negative y puts the text off the bottom edge of the page rect.
        return Overlay(payload, y=-140.0, size=9.0, color=(0.0, 0.0, 0.0))
    if placement == "behind_image":
        return Overlay(payload, y=150.0, size=8.0, color=(0.1, 0.1, 0.1),
                       cover_with_image=True)
    raise ValueError(f"unknown hidden_text placement {placement!r}")


def build(
    profile: dict[str, Any],
    payload: str,
    out_dir: Path,
    attack_id: str,
    *,
    placement: str = "white_text",
) -> Path:
    out_path = Path(out_dir) / f"{attack_id}.pdf"
    return render(profile, out_path, overlays=[_overlay_for(placement, payload)])
