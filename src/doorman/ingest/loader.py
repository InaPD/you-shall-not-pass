"""Dispatch a file to the right parser and evaluate the ING-* rules (spec 8.2)."""

from __future__ import annotations

from pathlib import Path

from doorman.config import Settings
from doorman.ingest import hidden, pdf
from doorman.models import Document

SUPPORTED_EXTENSIONS = (".pdf", ".docx")


class UnsupportedDocument(ValueError):
    pass


def load(path: Path | str, settings: Settings, *, evaluate_rules: bool = True) -> Document:
    """Parse `path` into a Document with ING-* rules already evaluated.

    Rules are evaluated regardless of config: spec 8.3 requires them to compute
    even when `hidden_text_rules` is off, so the baseline can report what it
    would have caught.
    """
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        doc = pdf.parse(path)
    elif suffix == ".docx":
        from doorman.ingest import docx  # noqa: PLC0415 - lands in Phase 3

        doc = docx.parse(path)
    else:
        raise UnsupportedDocument(
            f"{path.name}: expected one of {', '.join(SUPPORTED_EXTENSIONS)}"
        )
    return hidden.evaluate(doc, settings) if evaluate_rules else doc
