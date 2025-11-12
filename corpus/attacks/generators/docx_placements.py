"""`docx` family: carriers that only exist in Word documents (spec 16.2).

Comments, tracked deletions, alt text and hidden runs all survive in the file
while being absent from a normal reading view. Core properties are the DOCX
equivalent of the PDF Info dictionary.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from corpus.templates.docx_resume import DocxInjection, render

PLACEMENTS = (
    "docx_core_props",
    "docx_comment",
    "docx_tracked_change",
    "docx_alt_text",
    "docx_hidden_run",
    "docx_white_text",
    "docx_tiny_font",
    "docx_body",
)


def build(
    profile: dict[str, Any],
    payload: str,
    out_dir: Path,
    attack_id: str,
    *,
    placement: str = "docx_comment",
) -> Path:
    return render(
        profile,
        Path(out_dir) / f"{attack_id}.docx",
        injection=DocxInjection(placement, payload),
    )
