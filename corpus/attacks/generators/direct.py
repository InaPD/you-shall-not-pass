"""`direct` family: the payload is visible body text (spec 16.2).

The baseline placement. If an attack does not work here, a hidden variant of it
is not going to work either, so this family is the control for the rest.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from corpus.templates.pdf_resume import Section, render

PLACEMENTS = ("body_plain", "body_disguised")


def build(
    profile: dict[str, Any],
    payload: str,
    out_dir: Path,
    attack_id: str,
    *,
    placement: str = "body_plain",
) -> Path:
    out_path = Path(out_dir) / f"{attack_id}.pdf"
    if placement == "body_plain":
        section = Section("Additional Information", paragraphs=[payload])
    elif placement == "body_disguised":
        # Formatted as though a recruiter had pasted their own notes into the file.
        section = Section(
            "Recruiting Operations - Screening Record",
            paragraphs=[payload],
        )
    else:
        raise ValueError(f"unknown direct placement {placement!r}")
    return render(profile, out_path, extra_sections=[section])
