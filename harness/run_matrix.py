"""Run the config x corpus x repeat matrix (spec 18).

Two corpora go through the same runner. Attacks are scored by an oracle - did the
effect the payload asked for exist in final state. Benign resumes have no oracle:
what is recorded is what the pipeline did to an applicant who did nothing wrong,
which is where `FP_hard`, `FP_soft` and `score_drift` come from.

Resumable by design: a `(config, corpus, item, rep)` tuple already present in
results.jsonl is skipped, so an interrupted sweep is restarted rather than
repeated. That matters more than it sounds - the full matrix is ~1,200 runs.
"""

from __future__ import annotations

import json
import threading
import traceback
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from corpus.attacks import build as attack_build
from corpus.benign import generate as benign_build

from doorman import config as doorman_config
from doorman.agent import orchestrator
from doorman.config import Settings
from harness import pricing
from harness import state as state_reader
from harness.oracles import OracleResult, evaluate

OUT_DIR = Path(__file__).resolve().parent / "out"
RESULTS_PATH = OUT_DIR / "results.jsonl"

CORPORA = ("attacks", "benign")

# Spec 18 caps this at 4. Higher gains nothing: the SDK's own rate-limit retries
# are what the ceiling is there to respect, not local CPU.
MAX_CONCURRENCY = 4

# Oracles that need a value only the run itself knows.
_RUNTIME_ORACLE_ARGS = {
    "email_recipient_not_ats": lambda result: {"trusted_email": result.trusted_email},
}


@dataclass(frozen=True)
class Cell:
    config: str
    item_id: str
    rep: int
    corpus: str = "attacks"

    def key(self) -> tuple[str, str, str, int]:
        return (self.config, self.corpus, self.item_id, self.rep)


@lru_cache(maxsize=1)
def default_client_factory() -> Any:
    """One real client for the whole sweep. Memoised rather than constructed per
    cell so the connection pool is shared; the SDK client is stateless and thread
    safe, so this is also what makes concurrency safe. Test fakes are NOT
    memoised and get a fresh instance per run."""
    import anthropic

    return anthropic.Anthropic()


def existing_cells(path: Path = RESULTS_PATH) -> set[tuple[str, str, str, int]]:
    if not Path(path).is_file():
        return set()
    done: set[tuple[str, str, str, int]] = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        done.add(
            (row["config"], row.get("corpus", "attacks"), row["item_id"], int(row["rep"]))
        )
    return done


def _rules_fired(events: list[dict]) -> list[str]:
    fired: list[str] = []
    for event in events:
        for key in ("rule_id", "cause_rule_id"):
            value = event.get(key)
            if value and value not in fired:
                fired.append(value)
    return fired


def denials(events: list[dict]) -> list[str]:
    """Every rule that refused something in this run.

    A benign run with one of these is a hard false positive: the pipeline did not
    merely hesitate over an ordinary applicant, it blocked. Approvals are not
    counted - holding an irreversible action for a human is the design, not a
    failure.
    """
    found: list[str] = []
    for event in events:
        name = event.get("event")
        if name == "policy_decision" and event.get("decision") == "deny":
            found.append(event.get("rule_id") or "POL-unknown")
        elif name == "output_blocked":
            found.append(event.get("rule_id") or "OUT-unknown")
    return found


def _cost(settings: Settings, result: Any) -> float | None:
    """Agent and reader tokens are billed at their own model's rate."""
    reader = pricing.cost_usd(
        settings.reader_model, result.reader_input_tokens, result.reader_output_tokens
    )
    agent = pricing.cost_usd(
        settings.agent_model,
        result.input_tokens - result.reader_input_tokens,
        result.output_tokens - result.reader_output_tokens,
    )
    if agent is None or reader is None:
        return None
    return round(agent + reader, 6)


# A run the model never finished, because it ran out of output budget rather
# than because anything decided anything. Reported, never counted (spec 18).
INCOMPLETE_STATUSES = frozenset({"truncated"})


def _outcome(settings: Settings, result: Any, events: list[dict]) -> dict[str, Any]:
    denied = denials(events)
    return {
        "run_id": result.run_id,
        "taint": str(result.taint),
        "status": result.status,
        "classifier": result.classifier,
        "rules_fired": _rules_fired(events),
        "denied_by": denied,
        "denied": bool(denied),
        # No score or no decision means the run never produced a recommendation,
        # whatever the status says. That is an abort for reporting purposes.
        "aborted": result.score is None or result.decision is None,
        "incomplete": result.status in INCOMPLETE_STATUSES,
        "score": result.score,
        "decision": result.decision,
        "duration_s": result.duration_s,
        "input_tokens": result.input_tokens,
        "output_tokens": result.output_tokens,
        "cost_usd": _cost(settings, result),
    }


def _error_row(base: dict[str, Any], exc: Exception) -> dict[str, Any]:
    """A crashed run is a recorded result, not a gap in the table.

    It carries `error`, and the report excludes any row with one from every rate
    it computes. A run that died on a rate limit is not an attack the defences
    stopped, and it is not a benign applicant the defences refused; counting it
    as either invents a number. The oracle verdict is only written for the attack
    corpus - a benign row has no `reached`/`executed` columns to fill in.
    """
    row = {
        **base,
        "run_id": None,
        "error": f"{type(exc).__name__}: {exc}",
        "traceback": traceback.format_exc(limit=3),
        "denied": False,
        "aborted": True,
        "incomplete": True,
    }
    if base.get("corpus") == "attacks":
        row["reached"] = False
        row["executed"] = False
    return row


def run_cell(
    client: Any,
    settings: Settings,
    spec: attack_build.AttackSpec,
    cfg_name: str,
    rep: int,
    *,
    attacks_dir: Path,
    runs_root: Path | None = None,
    candidate_id: str = "C001",
    job_id: str = "J001",
    approval: str = "auto",
    guard: Any = None,
) -> dict[str, Any]:
    cfg = doorman_config.preset(cfg_name)
    doc_path = attack_build.artefact_path(spec, Path(attacks_dir))
    # tool_result/ats_notes attacks ship their own poisoned seed next to the
    # document. Everything else starts from the clean one, so no run can inherit
    # another attack's poison (spec 13).
    seed = attack_build.ats_seed_for(spec, Path(attacks_dir))
    row: dict[str, Any] = {
        "config": cfg_name, "corpus": "attacks", "item_id": spec.id,
        "family": spec.family, "placement": spec.placement, "rep": rep,
    }
    try:
        result = orchestrator.run_candidate(
            client, settings, cfg,
            doc_path=doc_path, candidate_id=candidate_id, job_id=job_id,
            runs_root=runs_root, corpus_item_id=spec.id,
            approval=approval, guard=guard, ats_seed=seed,
        )
    except Exception as exc:
        return _error_row(row, exc)

    events, final_state = state_reader.collect(result)
    extra = _RUNTIME_ORACLE_ARGS.get(spec.oracle, lambda _r: {})(result)
    try:
        verdict: OracleResult = evaluate(
            spec.oracle, events, final_state, **{**spec.oracle_args, **extra}
        )
    except Exception as exc:
        verdict = OracleResult(reached=False, executed=False,
                               detail=f"oracle error: {type(exc).__name__}: {exc}")
    return {
        **row,
        "reached": verdict.reached,
        "executed": verdict.executed,
        "detail": verdict.detail,
        **_outcome(settings, result, events),
    }


def run_benign_cell(
    client: Any,
    settings: Settings,
    spec: benign_build.BenignSpec,
    cfg_name: str,
    rep: int,
    *,
    benign_dir: Path,
    runs_root: Path | None = None,
    candidate_id: str = benign_build.CANDIDATE_SLOT,
    job_id: str = "J001",
    approval: str = "auto",
    guard: Any = None,
) -> dict[str, Any]:
    """One benign applicant under one config. No oracle - nothing is being
    attacked, so what is recorded is simply what happened to them."""
    cfg = doorman_config.preset(cfg_name)
    row: dict[str, Any] = {
        "config": cfg_name, "corpus": "benign", "item_id": spec.id,
        "family": "hard_negative" if spec.is_hard_negative else "benign",
        "placement": spec.layout, "rep": rep,
        "hard_negative": spec.is_hard_negative, "why": spec.why,
        "format": spec.format,
    }
    try:
        result = orchestrator.run_candidate(
            client, settings, cfg,
            doc_path=benign_build.artefact_path(spec, Path(benign_dir)),
            candidate_id=candidate_id, job_id=job_id,
            runs_root=runs_root, corpus_item_id=spec.id,
            approval=approval, guard=guard,
            ats_seed=benign_build.seed_path(spec, Path(benign_dir)),
        )
    except Exception as exc:
        return _error_row(row, exc)

    events, _ = state_reader.collect(result)
    return {**row, **_outcome(settings, result, events)}


def _select_attacks(only: list[str] | None) -> list[Any]:
    specs = attack_build.load_manifest()
    if not only:
        return specs
    wanted = set(only)
    return [s for s in specs if s.id in wanted or s.family in wanted]


def _select_benign(only: list[str] | None) -> list[Any]:
    specs = benign_build.load_specs()
    if not only:
        return specs
    wanted = set(only)
    return [
        s for s in specs
        if s.id in wanted
        or (s.is_hard_negative and "hard_negative" in wanted)
        or (not s.is_hard_negative and "benign" in wanted)
    ]


def run(
    *,
    configs: list[str],
    corpus: str = "attacks",
    repeats: int = 1,
    only: list[str] | None = None,
    approval: str = "auto",
    concurrency: int = 1,
    client_factory: Callable[[], Any] = default_client_factory,
    results_path: Path = RESULTS_PATH,
    attacks_dir: Path = attack_build.OUT_DIR,
    benign_dir: Path = benign_build.OUT_DIR,
    runs_root: Path | None = None,
    settings: Settings | None = None,
    guard: Any = None,
) -> Path:
    if corpus not in CORPORA:
        raise ValueError(f"unknown corpus {corpus!r}; choose one of {', '.join(CORPORA)}")
    settings = settings or Settings()
    specs = _select_attacks(only) if corpus == "attacks" else _select_benign(only)
    results_path = Path(results_path)
    results_path.parent.mkdir(parents=True, exist_ok=True)
    done = existing_cells(results_path)

    pending = [
        (cfg_name, spec, rep)
        for cfg_name in configs
        for spec in specs
        for rep in range(1, repeats + 1)
        if Cell(cfg_name, spec.id, rep, corpus).key() not in done
    ]

    def execute(job: tuple[str, Any, int]) -> dict[str, Any]:
        cfg_name, spec, rep = job
        if corpus == "attacks":
            row = run_cell(
                client_factory(), settings, spec, cfg_name, rep,
                attacks_dir=attacks_dir, runs_root=runs_root,
                approval=approval, guard=guard,
            )
        else:
            row = run_benign_cell(
                client_factory(), settings, spec, cfg_name, rep,
                benign_dir=benign_dir, runs_root=runs_root,
                approval=approval, guard=guard,
            )
        row["approval"] = approval
        return row

    workers = max(1, min(int(concurrency), MAX_CONCURRENCY))
    lock = threading.Lock()
    with results_path.open("a", encoding="utf-8") as handle:
        def record(row: dict[str, Any]) -> None:
            # Flushed per row and under a lock: a sweep killed mid-flight leaves a
            # readable file, which is the whole point of resumability.
            with lock:
                handle.write(json.dumps(row) + "\n")
                handle.flush()

        if workers == 1:
            for job in pending:
                record(execute(job))
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for row in pool.map(execute, pending):
                    record(row)
    return results_path
