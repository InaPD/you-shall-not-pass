"""Core data models (spec 7).

Every piece of data carried through the system is tagged with its trust level via
`Source`. The split that matters: `Document.visible_text()` is what the quarantined
reader is allowed to see, while `Document.guard_units()` is what the classifier and
the logs see. Hidden spans appear in the second and not the first.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Source(StrEnum):
    """Provenance of a piece of data. Everything except JOB_SPEC is untrusted in
    origin; see the trust table in spec 2."""

    DOC_TEXT = "doc_text"
    DOC_META = "doc_meta"
    TOOL_RESULT = "tool_result"
    ATS = "ats"
    JOB_SPEC = "job_spec"
    MODEL = "model"


# Span ids are "p{page}-b{block}-l{line}-s{span}" (spec 7). Parsed to reconstruct
# reading order; anything that does not match is treated as its own line.
_SPAN_ID_RE = re.compile(r"^p(\d+)-b(\d+)-l(\d+)-s(\d+)$")


class Span(BaseModel):
    id: str
    page: int
    text: str
    bbox: tuple[float, float, float, float]
    size: float
    color_rgb: tuple[int, int, int]
    hidden_reasons: list[str] = Field(default_factory=list)  # ING-* ids; empty => visible

    @property
    def is_hidden(self) -> bool:
        return bool(self.hidden_reasons)


def _layout_key(span: Span, index: int) -> tuple[int, int, int]:
    """(page, block, line) for grouping. Falls back to a unique line per span."""
    match = _SPAN_ID_RE.match(span.id)
    if match is None:
        return (span.page, -1, index)
    page, block, line, _ = (int(g) for g in match.groups())
    return (page, block, line)


class Document(BaseModel):
    doc_id: str
    kind: Literal["pdf", "docx"]
    sha256: str
    page_count: int
    spans: list[Span]
    # Flattened, e.g. "pdf.info.author", "pdf.xmp.dc:description", "docx.core.keywords",
    # "docx.comment.3", "docx.tracked.del.7".
    metadata: dict[str, str] = Field(default_factory=dict)
    metadata_flags: dict[str, list[str]] = Field(default_factory=dict)  # key -> ING-* ids

    # Layout facts that ING-003 and ING-004 need and that nothing else may use.
    # Not in the spec 7 model: those two rules are geometric tests and cannot run
    # without them. PDF only; DOCX leaves both empty.
    page_rects: dict[int, tuple[float, float, float, float]] = Field(default_factory=dict)
    image_rects: dict[int, list[tuple[float, float, float, float]]] = Field(
        default_factory=dict
    )

    def visible_spans(self, *, exclude_hidden: bool = True) -> list[Span]:
        if not exclude_hidden:
            return list(self.spans)
        return [s for s in self.spans if not s.is_hidden]

    def hidden_spans(self) -> list[Span]:
        return [s for s in self.spans if s.is_hidden]

    def visible_text(self, *, exclude_hidden: bool = True) -> str:
        """Reading-order text with page breaks marked.

        `exclude_hidden` is driven by `DefenseConfig.hidden_text_rules`: when the
        ING-* rules are off, nothing is excluded (spec 8.3), which is what makes
        `isolation_only` a meaningful ablation against `full_minus_classifier`.
        """
        spans = self.visible_spans(exclude_hidden=exclude_hidden)
        lines: list[str] = []
        parts: list[str] = []
        prev: tuple[int, int, int] | None = None

        def flush() -> None:
            if parts:
                lines.append("".join(parts))
                parts.clear()

        for index, span in enumerate(spans):
            key = _layout_key(span, index)
            if prev is not None:
                if key[0] != prev[0]:
                    flush()
                    lines.append(f"\n--- page {key[0]} ---\n")
                elif key[1] != prev[1]:
                    flush()
                    lines.append("")  # blank line between blocks
                elif key[2] != prev[2]:
                    flush()
            parts.append(span.text)
            prev = key
        flush()
        return "\n".join(lines).strip()

    def metadata_dump(self) -> str:
        """Every metadata key and value as text. Only the undefended single-call
        flow (spec 12.3) is allowed to put this in a prompt."""
        return "\n".join(f"{key}: {value}" for key, value in sorted(self.metadata.items()))

    def guard_units(self) -> list[tuple[Source, str, str]]:
        """(source, locator, text) for EVERY span - visible and hidden - and EVERY
        metadata value. This is the classifier's and the log's view of the document.

        Nothing is filtered here, deliberately. A whitespace-looking span may carry
        zero-width characters (ING-005), so "empty" spans are not safe to drop.
        """
        units: list[tuple[Source, str, str]] = [
            (Source.DOC_TEXT, span.id, span.text) for span in self.spans
        ]
        units.extend((Source.DOC_META, key, value) for key, value in self.metadata.items())
        return units


class Degree(StrEnum):
    NONE = "none"
    HIGH_SCHOOL = "high_school"
    BACHELOR = "bachelor"
    MASTER = "master"
    PHD = "phd"
    OTHER = "other"


class Education(BaseModel):
    model_config = ConfigDict(extra="forbid")

    degree: Degree
    field: str = Field(max_length=60)
    institution: str = Field(max_length=80)
    year: int | None = Field(default=None, ge=1950, le=2030)


class CandidateProfile(BaseModel):
    """Output of the quarantined reader. Typed, capped, no channel for instructions."""

    model_config = ConfigDict(extra="forbid")

    years_experience: int = Field(ge=0, le=60)
    current_title: str = Field(max_length=80)
    skills: list[str] = Field(max_length=30)  # post-normalised to taxonomy; unknown dropped
    education: list[Education] = Field(max_length=6)
    languages: list[str] = Field(max_length=8)
    portfolio_url: str | None = Field(default=None, max_length=200)  # the ONLY url-typed field
    summary: str = Field(max_length=300)
    reader_confidence: float = Field(ge=0.0, le=1.0)


class JobSpec(BaseModel):
    job_id: str
    title: str
    required_skills: list[str]
    nice_to_have: list[str]
    min_years: int
    description: str


class ATSRecord(BaseModel):
    candidate_id: str
    job_id: str
    full_name: str  # TRUSTED - set by recruiters
    email: str  # TRUSTED - set by recruiters
    status: Literal["new", "screening", "hold", "advance", "reject"]
    notes: str = ""  # UNTRUSTED - free text of unknown provenance
    applied_at: str


class Taint(StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"


class Phase(StrEnum):
    INGEST = "ingest"
    EXTRACT = "extract"
    SCORE = "score"
    DECIDE = "decide"
    COMMUNICATE = "communicate"
    WRITE_ATS = "write_ats"
    REVIEW = "review"
    SINGLE = "single"  # none / prompt_only configs


class ToolCall(BaseModel):
    id: str
    name: str
    input: dict
    phase: Phase


class Allow(BaseModel):
    kind: Literal["allow"] = "allow"


class Deny(BaseModel):
    kind: Literal["deny"] = "deny"
    rule_id: str
    reason: str


class RequireApproval(BaseModel):
    kind: Literal["approve"] = "approve"
    rule_id: str
    reason: str


PolicyDecision = Allow | Deny | RequireApproval


class RunContext(BaseModel):
    run_id: str
    trace_id: str
    config_name: str
    candidate_id: str
    job_id: str
    phase: Phase = Phase.INGEST
    taint: Taint = Taint.CLEAN
    canary: str  # random 16-hex per run, embedded in the agent system prompt
    trusted_email: str  # copied from ATSRecord
    trusted_full_name: str  # copied from ATSRecord
    trusted_urls: set[str] = Field(default_factory=set)
    budgets_used: dict[str, int] = Field(default_factory=dict)
    batch_candidate_ids: set[str] = Field(default_factory=set)  # for OUT-004
