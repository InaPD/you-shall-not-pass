"""Phase state machine (spec 12.3).

Phase 1 implements the single-call flow used by `none` and `prompt_only`. The
phased flow lands in Phase 2.

Phase transitions are decided here, in code. Never by the model, and never by a
tool result (spec 21.2).
"""

from __future__ import annotations

import secrets
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from doorman import trace
from doorman.agent import prompts
from doorman.agent.loop import Router, run_phase
from doorman.agent.tools import NAIVE_TOOLS, tools_for
from doorman.config import CONFIG_DIR, DefenseConfig, Settings, run_dir
from doorman.guard import scan as guard_scan
from doorman.guard.classifier import Guard, build_guard
from doorman.ingest import hidden, loader
from doorman.models import (
    ATSRecord,
    CandidateProfile,
    Document,
    JobSpec,
    Phase,
    RunContext,
    Taint,
)
from doorman.policy import engine
from doorman.policy import phases as phase_defs
from doorman.reader import quarantined
from doorman.reader.quarantined import ReaderFailed
from doorman.tools.ats import ATS
from doorman.tools.email import Outbox

CORPUS_ROOT = CONFIG_DIR.parent / "corpus"
DEFAULT_ATS_SEED = CORPUS_ROOT / "fixtures" / "ats_seed.yaml"
JOB_SPEC_DIR = CONFIG_DIR / "job_specs"


@dataclass
class RunResult:
    run_id: str
    config_name: str
    candidate_id: str
    status: str
    score: int | None = None
    decision: str | None = None
    taint: Taint = Taint.CLEAN
    rules_fired: list[str] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    # Split out because the reader runs on a different model at a different
    # price; one combined number cannot be costed (spec 18).
    reader_input_tokens: int = 0
    reader_output_tokens: int = 0
    duration_s: float = 0.0
    doc_sha256: str = ""
    classifier: str = ""
    canary: str = ""          # needed by the canary_leaked oracle
    trusted_email: str = ""   # needed by the email_recipient_not_ats oracle
    events_path: Path | None = None
    outbox_path: Path | None = None
    ats_path: Path | None = None


def load_job_spec(job_id: str, directory: Path = JOB_SPEC_DIR) -> JobSpec:
    path = Path(directory) / f"{job_id}.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"no job spec for {job_id!r} at {path}")
    return JobSpec(**yaml.safe_load(path.read_text(encoding="utf-8")))


def new_run_id() -> str:
    return f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"


def _save_document(doc: Document, directory: Path) -> None:
    """Spec 15: the Document is kept for debugging. Never logged inline."""
    out = directory / "documents"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{doc.doc_id}.json").write_text(doc.model_dump_json(indent=2), encoding="utf-8")


def _apply_ingestion_taint(ctx: RunContext, doc: Document, cfg: DefenseConfig) -> list[str]:
    """Log every ING-* hit; flip taint only when the rules are switched on."""
    for span in doc.hidden_spans():
        for rule_id in span.hidden_reasons:
            trace.hidden_text_detected(
                ctx,
                rule_id=rule_id,
                span_id=span.id,
                size=span.size,
                color_rgb=span.color_rgb,
                text_len=len(span.text),
            )
    for key, reasons in doc.metadata_flags.items():
        for rule_id in reasons:
            trace.hidden_text_detected(
                ctx, rule_id=rule_id, metadata_key=key, text_len=len(doc.metadata[key])
            )

    fired = hidden.fired_rules(doc)
    causes = hidden.taint_causes(doc)
    if cfg.hidden_text_rules and causes:
        trace.taint_changed(
            ctx, from_taint=ctx.taint, to_taint=Taint.SUSPICIOUS, cause_rule_id=causes[0]
        )
        ctx.taint = Taint.SUSPICIOUS
    return fired


def _single_call(
    client: Any,
    settings: Settings,
    cfg: DefenseConfig,
    ctx: RunContext,
    *,
    doc: Document,
    job: JobSpec,
    router: Router,
) -> Any:
    """The undefended flow: everything in one prompt, every call executed."""
    ctx.phase = Phase.SINGLE
    system = prompts.single_call_system(
        job=job,
        record=router.ats.get(ctx.candidate_id),
        doc=doc,
        canary=ctx.canary,
        polite=cfg.polite_prompt,
    )
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": prompts.SINGLE_CALL_TASK}
    ]
    return run_phase(
        client,
        settings,
        cfg,
        ctx,
        system=system,
        messages=messages,
        tools=NAIVE_TOOLS,
        router=router,
        max_turns=settings.max_turns_single_call,
        is_complete=lambda r: r.email_sent and r.ats_written,
    )


def run_candidate(
    client: Any,
    settings: Settings,
    cfg: DefenseConfig,
    *,
    doc_path: Path,
    candidate_id: str,
    job_id: str,
    run_id: str | None = None,
    runs_root: Path | None = None,
    ats_seed: Path = DEFAULT_ATS_SEED,
    corpus_item_id: str | None = None,
    approval: str = "auto",
    guard: Guard | None = None,
) -> RunResult:
    """Screen one candidate end to end under `cfg`."""
    started = time.perf_counter()
    run_id = run_id or new_run_id()
    directory = Path(runs_root) / run_id if runs_root else run_dir(run_id)
    directory.mkdir(parents=True, exist_ok=True)

    events_path = trace.open_run(run_id, directory)
    try:
        ats = ATS.seeded(directory / "ats.db", ats_seed)
        outbox = Outbox(directory / "outbox.jsonl")
        record = ats.get(candidate_id)
        job = load_job_spec(job_id)
        doc = loader.load(doc_path, settings)
        _save_document(doc, directory)

        ctx = RunContext(
            run_id=run_id,
            trace_id=uuid.uuid4().hex,
            config_name=cfg.name,
            candidate_id=candidate_id,
            job_id=job_id,
            canary=secrets.token_hex(8),
            trusted_email=record.email,
            trusted_full_name=record.full_name,
            batch_candidate_ids=ats.other_candidate_ids(candidate_id),
            batch_candidate_names={
                record_.full_name
                for record_ in ats.all_candidates()
                if record_.candidate_id != candidate_id
            },
        )
        active_guard = guard if guard is not None else build_guard(cfg.classifier)
        trace.run_started(
            ctx,
            agent_model=settings.agent_model,
            reader_model=settings.reader_model,
            config=cfg.as_dict(),
            doc_sha256=doc.sha256,
            corpus_item_id=corpus_item_id,
            classifier=getattr(active_guard, "name", type(active_guard).__name__),
        )

        rules_fired = _apply_ingestion_taint(ctx, doc, cfg)

        # Advisory heuristics always run; the classifier only when enabled.
        rules_fired += guard_scan.scan_heuristics(doc, ctx)
        summary = guard_scan.scan_document(doc, ctx, cfg, settings, active_guard)
        rules_fired += summary.flagged

        router = Router(
            ctx=ctx, cfg=cfg, settings=settings, ats=ats, outbox=outbox,
            approval_mode=approval, guard=active_guard,
        )

        if cfg.phase_allowlists:
            phase_result = _phased(
                client, settings, cfg, ctx, doc=doc, job=job, record=record, router=router
            )
        else:
            phase_result = _single_call(
                client, settings, cfg, ctx, doc=doc, job=job, router=router
            )

        duration = time.perf_counter() - started
        trace.run_finished(
            ctx,
            status=phase_result.status,
            score=router.score,
            decision=router.decision,
            duration_s=round(duration, 3),
            total_input_tokens=phase_result.input_tokens,
            total_output_tokens=phase_result.output_tokens,
        )
        return RunResult(
            run_id=run_id,
            config_name=cfg.name,
            candidate_id=candidate_id,
            status=phase_result.status,
            score=router.score,
            decision=router.decision,
            taint=ctx.taint,
            rules_fired=sorted(set(rules_fired)),
            input_tokens=phase_result.input_tokens,
            output_tokens=phase_result.output_tokens,
            reader_input_tokens=getattr(phase_result, "reader_input_tokens", 0),
            reader_output_tokens=getattr(phase_result, "reader_output_tokens", 0),
            duration_s=round(duration, 3),
            doc_sha256=doc.sha256,
            classifier=getattr(active_guard, "name", type(active_guard).__name__),
            canary=ctx.canary,
            trusted_email=ctx.trusted_email,
            events_path=events_path,
            outbox_path=outbox.path,
            ats_path=ats.path,
        )
    finally:
        trace.close_run(run_id)

# --- Phased flow (spec 12.3) -------------------------------------------------


def _allowed_hosts(profile: CandidateProfile) -> set[str]:
    from urllib.parse import urlparse

    if not profile.portfolio_url:
        return set()
    parsed = urlparse(profile.portfolio_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return set()
    return {parsed.hostname}


def _trust_portfolio_url(ctx: RunContext, profile: CandidateProfile,
                         cfg: DefenseConfig) -> None:
    """Spec 9: the portfolio host is trusted only when it parses and is allowed."""
    hosts = _allowed_hosts(profile)
    if not hosts:
        return
    ctx.trusted_portfolio_url = profile.portfolio_url
    if cfg.output_scan:
        ctx.trusted_urls |= hosts


def _run_one_phase(
    client: Any,
    settings: Settings,
    cfg: DefenseConfig,
    ctx: RunContext,
    router: Router,
    *,
    phase: Phase,
    system: str,
    task: str,
    is_complete: Any,
) -> Any:
    """Each phase gets a fresh message list. Phases never share history; typed
    outputs are passed forward in the next phase's prompt (spec 12.3)."""
    ctx.phase = phase
    return run_phase(
        client,
        settings,
        cfg,
        ctx,
        system=system,
        messages=[{"role": "user", "content": task}],
        tools=tools_for(cfg.hardened_tools, phase_defs.allowed(phase)),
        router=router,
        max_turns=settings.max_turns_per_phase,
        evaluate=engine.evaluate,
        is_complete=is_complete,
    )


def _review(
    ctx: RunContext,
    router: Router,
    *,
    cause_rule_id: str | None = None,
    reason: str | None = None,
) -> None:
    """Code calls the review tool directly; the model is not consulted."""
    ctx.phase = Phase.REVIEW
    trace.review_requested(ctx, cause_rule_id=cause_rule_id, reason=reason)
    router.review_requested = True


def _phased(
    client: Any,
    settings: Settings,
    cfg: DefenseConfig,
    ctx: RunContext,
    *,
    doc: Document,
    job: JobSpec,
    record: ATSRecord,
    router: Router,
) -> Any:
    totals = PhaseTotals()

    # --- extract -------------------------------------------------------------
    ctx.phase = Phase.EXTRACT
    try:
        profile, used_in, used_out = quarantined.read_profile(
            client, settings, cfg, ctx, doc
        )
    except ReaderFailed:
        _review(ctx, router, reason="reader_failed")
        return PhaseResultLike("review", totals)
    totals.add(used_in, used_out, reader=True)
    _trust_portfolio_url(ctx, profile, cfg)

    # --- score ---------------------------------------------------------------
    result = _run_one_phase(
        client, settings, cfg, ctx, router,
        phase=Phase.SCORE,
        system=prompts.score_system(
            job=job, profile=profile, canary=ctx.canary, polite=cfg.polite_prompt
        ),
        task=prompts.PHASE_TASKS["score"],
        is_complete=lambda r: r.score is not None,
    )
    totals.add(result.input_tokens, result.output_tokens)
    if result.status == "truncated":
        return PhaseResultLike("truncated", totals)
    if router.score is None:
        _review(ctx, router, reason="no_score_recorded")
        return PhaseResultLike("review", totals)
    score_rationale = router.rationale

    # --- decide --------------------------------------------------------------
    result = _run_one_phase(
        client, settings, cfg, ctx, router,
        phase=Phase.DECIDE,
        system=prompts.decide_system(
            job=job, profile=profile, score=router.score, rationale=score_rationale,
            canary=ctx.canary, polite=cfg.polite_prompt,
        ),
        task=prompts.PHASE_TASKS["decide"],
        is_complete=lambda r: r.decision is not None,
    )
    totals.add(result.input_tokens, result.output_tokens)
    if result.status == "truncated":
        return PhaseResultLike("truncated", totals)
    if router.decision is None:
        _review(ctx, router, reason="no_decision_recorded")
        return PhaseResultLike("review", totals)

    # --- taint gate ----------------------------------------------------------
    # Spec 11.2: a suspicious document still gets scored and decided, so the
    # recruiter receives a recommendation - it just never reaches the outside
    # world on its own. POL-002 would also deny these tools; the redundancy is
    # deliberate and both halves must stay.
    if ctx.taint is Taint.SUSPICIOUS:
        _review(ctx, router, cause_rule_id="POL-002")  # the taint gate is a real rule
        return PhaseResultLike("review", totals)

    # --- communicate ---------------------------------------------------------
    result = _run_one_phase(
        client, settings, cfg, ctx, router,
        phase=Phase.COMMUNICATE,
        system=prompts.communicate_system(
            full_name=record.full_name, status=router.decision,
            rationale=router.rationale, canary=ctx.canary, polite=cfg.polite_prompt,
        ),
        task=prompts.PHASE_TASKS["communicate"],
        is_complete=lambda r: r.email_sent or r.email_pending,
    )
    totals.add(result.input_tokens, result.output_tokens)
    if result.status == "truncated":
        return PhaseResultLike("truncated", totals)

    # --- write_ats -----------------------------------------------------------
    result = _run_one_phase(
        client, settings, cfg, ctx, router,
        phase=Phase.WRITE_ATS,
        system=prompts.write_ats_system(
            status=router.decision, rationale=router.rationale,
            canary=ctx.canary, polite=cfg.polite_prompt,
        ),
        task=prompts.PHASE_TASKS["write_ats"],
        is_complete=lambda r: r.ats_written or r.ats_pending,
    )
    totals.add(result.input_tokens, result.output_tokens)
    if result.status == "truncated":
        return PhaseResultLike("truncated", totals)
    return PhaseResultLike("done", totals)


@dataclass
class PhaseTotals:
    input_tokens: int = 0
    output_tokens: int = 0
    reader_input_tokens: int = 0
    reader_output_tokens: int = 0

    def add(self, used_in: int, used_out: int, *, reader: bool = False) -> None:
        self.input_tokens += used_in
        self.output_tokens += used_out
        if reader:
            self.reader_input_tokens += used_in
            self.reader_output_tokens += used_out


@dataclass
class PhaseResultLike:
    status: str
    totals: PhaseTotals

    @property
    def input_tokens(self) -> int:
        return self.totals.input_tokens

    @property
    def output_tokens(self) -> int:
        return self.totals.output_tokens

    @property
    def reader_input_tokens(self) -> int:
        return self.totals.reader_input_tokens

    @property
    def reader_output_tokens(self) -> int:
        return self.totals.reader_output_tokens
