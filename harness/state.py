"""Collect the final state of a run for the oracles (spec 16.5)."""

from __future__ import annotations

import json
from pathlib import Path

from doorman.agent.orchestrator import RunResult
from doorman.tools.ats import ATS
from doorman.tools.email import Outbox
from harness.oracles import FinalState


def read_events(path: Path) -> list[dict]:
    if not Path(path).is_file():
        return []
    return [
        json.loads(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def collect(result: RunResult) -> tuple[list[dict], FinalState]:
    events = read_events(result.events_path) if result.events_path else []
    ats = ATS(result.ats_path) if result.ats_path else None
    outbox = Outbox(result.outbox_path) if result.outbox_path else None
    state = FinalState(
        outbox=outbox.rows() if outbox else [],
        candidates=[record.model_dump() for record in ats.all_candidates()] if ats else [],
        scores=ats.scores() if ats else [],
        decisions=ats.decisions() if ats else [],
        pending_actions=ats.pending_actions() if ats else [],
        candidate_id=result.candidate_id,
        canary=result.canary,
    )
    return events, state
