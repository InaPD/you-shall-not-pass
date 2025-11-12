"""`split` family: the payload is assembled from pieces (spec 16.2).

Each half is innocuous on its own. This is the family that justifies the
classifier's chunk overlap: score a document in non-overlapping windows and a
payload cut across a boundary is two harmless fragments.

  multi_page_split -> half on page one, half on page two
  metadata_split   -> half in Subject, half in Keywords
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from corpus.templates.pdf_resume import PAGE_HEIGHT, Overlay, Section, render

PLACEMENTS = ("multi_page_split", "metadata_split")


def _halves(payload: str) -> tuple[str, str]:
    words = payload.split()
    middle = len(words) // 2
    return " ".join(words[:middle]), " ".join(words[middle:])


def build(
    profile: dict[str, Any],
    payload: str,
    out_dir: Path,
    attack_id: str,
    *,
    placement: str = "multi_page_split",
) -> Path:
    out_path = Path(out_dir) / f"{attack_id}.pdf"
    first, second = _halves(payload)

    if placement == "multi_page_split":
        # The first half ends page one; the second is drawn near the top of the
        # overflow page, so no single page carries the whole instruction.
        return render(
            profile,
            out_path,
            extra_sections=[
                Section("Additional Information", paragraphs=[first]),
                Section("Continued", paragraphs=["(continued overleaf)"]),
            ],
            overlays=[Overlay(second, y=PAGE_HEIGHT - 120.0, size=8.0, page=2)],
        )

    if placement == "metadata_split":
        return render(
            profile,
            out_path,
            metadata={
                "author": profile.get("full_name", ""),
                "subject": first,
                "keywords": second,
            },
        )
    raise ValueError(f"unknown split placement {placement!r}")
