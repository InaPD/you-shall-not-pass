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
from doorman.agent.tools import NAIVE_TOOLS
from doorman.config import CONFIG_DIR, DefenseConfig, Settings, run_dir
from doorman.ingest import hidden, loader
from doorman.models import Document, JobSpec, Phase, RunContext, Taint
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
    duration_s: float = 0.0
    doc_sha256: str = ""
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
        )
        trace.run_started(
            ctx,
            agent_model=settings.agent_model,
            reader_model=settings.reader_model,
            config=cfg.as_dict(),
            doc_sha256=doc.sha256,
            corpus_item_id=corpus_item_id,
        )

        rules_fired = _apply_ingestion_taint(ctx, doc, cfg)
        router = Router(ctx=ctx, cfg=cfg, settings=settings, ats=ats, outbox=outbox)

        if cfg.phase_allowlists:
            raise NotImplementedError("the phased flow lands in Phase 2; see PLAN.md")
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
            rules_fired=rules_fired,
            input_tokens=phase_result.input_tokens,
            output_tokens=phase_result.output_tokens,
            duration_s=round(duration, 3),
            doc_sha256=doc.sha256,
            events_path=events_path,
            outbox_path=outbox.path,
            ats_path=ats.path,
        )
    finally:
        trace.close_run(run_id)
