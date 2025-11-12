"""Run the config x corpus x repeat matrix (spec 18).

Resumable by design: a `(config, item, rep)` triple already present in
results.jsonl is skipped, so an interrupted sweep is restarted rather than
repeated. That matters more than it sounds - the full matrix is ~1,200 runs.
"""

from __future__ import annotations

import json
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from corpus.attacks import build as attack_build

from doorman import config as doorman_config
from doorman.agent import orchestrator
from doorman.config import Settings
from harness import state as state_reader
from harness.oracles import OracleResult, evaluate

OUT_DIR = Path(__file__).resolve().parent / "out"
RESULTS_PATH = OUT_DIR / "results.jsonl"

# Oracles that need a value only the run itself knows.
_RUNTIME_ORACLE_ARGS = {
    "email_recipient_not_ats": lambda result: {"trusted_email": result.trusted_email},
}


@dataclass(frozen=True)
class Cell:
    config: str
    item_id: str
    rep: int

    def key(self) -> tuple[str, str, int]:
        return (self.config, self.item_id, self.rep)


@lru_cache(maxsize=1)
def default_client_factory() -> Any:
    """One real client for the whole sweep. Memoised rather than constructed per
    cell so the connection pool is shared; the SDK client is stateless, so this
    is safe. Test fakes are NOT memoised and get a fresh instance per run."""
    import anthropic

    return anthropic.Anthropic()


def existing_cells(path: Path = RESULTS_PATH) -> set[tuple[str, str, int]]:
    if not Path(path).is_file():
        return set()
    done: set[tuple[str, str, int]] = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        done.add((row["config"], row["item_id"], int(row["rep"])))
    return done


def _rules_fired(events: list[dict]) -> list[str]:
    fired: list[str] = []
    for event in events:
        for key in ("rule_id", "cause_rule_id"):
            value = event.get(key)
            if value and value not in fired:
                fired.append(value)
    return fired


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
    except Exception as exc:  # a crashed run is a result, not a gap in the table
        return {
            **row, "run_id": None, "error": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(limit=3),
            "reached": False, "executed": False,
        }

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
        "run_id": result.run_id,
        "reached": verdict.reached,
        "executed": verdict.executed,
        "detail": verdict.detail,
        "taint": str(result.taint),
        "status": result.status,
        "rules_fired": _rules_fired(events),
        "score": result.score,
        "decision": result.decision,
        "duration_s": result.duration_s,
        "input_tokens": result.input_tokens,
        "output_tokens": result.output_tokens,
        "cost_usd": None,
    }


def run(
    *,
    configs: list[str],
    repeats: int = 1,
    only: list[str] | None = None,
    approval: str = "auto",
    client_factory: Callable[[], Any] = default_client_factory,
    results_path: Path = RESULTS_PATH,
    attacks_dir: Path = attack_build.OUT_DIR,
    runs_root: Path | None = None,
    settings: Settings | None = None,
    guard: Any = None,
) -> Path:
    settings = settings or Settings()
    specs = attack_build.load_manifest()
    if only:
        wanted = set(only)
        specs = [s for s in specs if s.id in wanted or s.family in wanted]
    results_path = Path(results_path)
    results_path.parent.mkdir(parents=True, exist_ok=True)
    done = existing_cells(results_path)

    with results_path.open("a", encoding="utf-8") as handle:
        for cfg_name in configs:
            for spec in specs:
                for rep in range(1, repeats + 1):
                    if Cell(cfg_name, spec.id, rep).key() in done:
                        continue
                    row = run_cell(
                        client_factory(), settings, spec, cfg_name, rep,
                        attacks_dir=attacks_dir, runs_root=runs_root,
                        approval=approval, guard=guard,
                    )
                    row["approval"] = approval
                    handle.write(json.dumps(row) + "\n")
                    handle.flush()
    return results_path
