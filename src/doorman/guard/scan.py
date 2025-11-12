"""Document-level classifier pass, CLS-001 and CLS-002 (spec 10.1).

Runs over every guard unit: every span, visible and hidden, and every metadata
value. A hit downgrades taint and nothing else - it never drops a span and never
blocks a call (spec 21.3).

This is the layer that catches the metadata family. Those attacks fire only
ING-009, which by design does not flip taint (metadata never reaches the reader),
so without the classifier they pass straight through to the agent's tool results.
"""

from __future__ import annotations

from dataclasses import dataclass

from doorman import trace
from doorman.config import DefenseConfig, Settings
from doorman.guard import heuristics
from doorman.guard.classifier import Guard, score_unit
from doorman.models import Document, RunContext, Source, Taint

# Which rule a hit reports, by where the text came from.
RULE_BY_SOURCE = {
    Source.DOC_TEXT: "CLS-001",
    Source.DOC_META: "CLS-002",
    Source.TOOL_RESULT: "CLS-003",
}


@dataclass
class ScanSummary:
    units: int = 0
    flagged: list[str] = None  # rule ids that fired, in order

    def __post_init__(self) -> None:
        self.flagged = self.flagged or []


def scan_document(
    doc: Document,
    ctx: RunContext,
    cfg: DefenseConfig,
    settings: Settings,
    guard: Guard,
) -> ScanSummary:
    """Score every guard unit. Returns what fired; mutates taint on ctx."""
    summary = ScanSummary()
    if not cfg.classifier:
        return summary

    threshold = settings.classifier_threshold
    for source, locator, text in doc.guard_units():
        if not text.strip():
            continue
        summary.units += 1
        score, chunk_index = score_unit(
            guard, text,
            size=settings.classifier_chunk_tokens,
            overlap=settings.classifier_chunk_overlap,
        )
        rule_id = RULE_BY_SOURCE[source] if score >= threshold else None
        trace.classifier_verdict(
            ctx, rule_id=rule_id, source=str(source), locator=locator,
            score=round(score, 4), chunk_index=chunk_index, threshold=threshold,
        )
        if rule_id is None:
            continue
        summary.flagged.append(rule_id)
        if ctx.taint is not Taint.SUSPICIOUS:
            trace.taint_changed(
                ctx, from_taint=ctx.taint, to_taint=Taint.SUSPICIOUS,
                cause_rule_id=rule_id,
            )
            ctx.taint = Taint.SUSPICIOUS
    return summary


def scan_heuristics(doc: Document, ctx: RunContext) -> list[str]:
    """CLS-101 / CLS-102. Advisory: logged, never changes taint (spec 10.2).

    Always runs, in every config. Their whole purpose is to sit alongside the
    structural layers in the report and show that phrase-matching is not what is
    doing the work.
    """
    fired: list[str] = []
    for _source, locator, text in doc.guard_units():
        for rule_id, matched in heuristics.evaluate(text):
            fired.append(rule_id)
            trace.heuristic_flagged(
                ctx, rule_id=rule_id, locator=locator,
                match_redacted=matched[:24], text_len=len(text),
            )
    return fired
