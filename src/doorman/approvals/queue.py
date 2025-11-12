"""Approval queue for irreversible actions (spec 14).

An action that reaches here has already passed every policy check; the queue is
the last gate before something leaves the system. Nothing is executed while a row
is pending, so a crash between queueing and resolution fails closed.

Resolvers:
  human        - `doorman approve` walks the queue interactively
  harness-auto - approves immediately, for `--approval auto` sweeps
  harness-deny - rejects immediately, for `--approval deny` sweeps

A note on measurement: under `harness-auto` every queued action resolves, so an
oracle asking "did this execute without a human?" is trivially true for benign
runs too. The `skip_confirmation` intent is only meaningful under deny or human.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from doorman.tools.ats import ATS

MODES = ("auto", "deny", "human")
RESOLVERS = {"auto": "harness-auto", "deny": "harness-deny"}

PENDING = "pending"
APPROVED = "approved"
REJECTED = "rejected"


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class PendingAction:
    id: int
    run_id: str
    trace_id: str
    candidate_id: str
    tool: str
    args: dict[str, Any]
    rule_id: str
    status: str
    created_at: str
    resolved_at: str | None = None
    resolver: str | None = None

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> PendingAction:
        return cls(
            id=int(row["id"]),
            run_id=row["run_id"] or "",
            trace_id=row["trace_id"] or "",
            candidate_id=row["candidate_id"] or "",
            tool=row["tool"] or "",
            args=json.loads(row["args_json"] or "{}"),
            rule_id=row["rule_id"] or "",
            status=row["status"] or PENDING,
            created_at=row["created_at"] or "",
            resolved_at=row["resolved_at"],
            resolver=row["resolver"],
        )


@dataclass
class ApprovalQueue:
    ats: ATS

    def enqueue(
        self, *, run_id: str, trace_id: str, candidate_id: str, tool: str,
        args: dict[str, Any], rule_id: str,
    ) -> int:
        with self.ats.connect() as conn:
            cursor = conn.execute(
                "INSERT INTO pending_actions "
                "(run_id, trace_id, candidate_id, tool, args_json, rule_id, "
                " created_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, trace_id, candidate_id, tool, json.dumps(args, sort_keys=True),
                 rule_id, _now(), PENDING),
            )
            return int(cursor.lastrowid)

    def get(self, action_id: int) -> PendingAction:
        with self.ats.connect() as conn:
            row = conn.execute(
                "SELECT * FROM pending_actions WHERE id = ?", (action_id,)
            ).fetchone()
        if row is None:
            raise KeyError(f"no pending action {action_id}")
        return PendingAction.from_row(dict(row))

    def pending(self, run_id: str | None = None) -> list[PendingAction]:
        query = "SELECT * FROM pending_actions WHERE status = ?"
        params: tuple[Any, ...] = (PENDING,)
        if run_id:
            query += " AND run_id = ?"
            params += (run_id,)
        with self.ats.connect() as conn:
            rows = conn.execute(query + " ORDER BY id", params).fetchall()
        return [PendingAction.from_row(dict(row)) for row in rows]

    def resolve(self, action_id: int, *, approved: bool, resolver: str) -> PendingAction:
        action = self.get(action_id)
        if action.status != PENDING:
            raise ValueError(f"action {action_id} is already {action.status}")
        with self.ats.connect() as conn:
            conn.execute(
                "UPDATE pending_actions SET status = ?, resolved_at = ?, resolver = ? "
                "WHERE id = ?",
                (APPROVED if approved else REJECTED, _now(), resolver, action_id),
            )
        return self.get(action_id)


def auto_resolver(mode: str) -> tuple[bool, str] | None:
    """(approved, resolver) for a non-interactive mode, or None for human."""
    if mode == "auto":
        return True, RESOLVERS["auto"]
    if mode == "deny":
        return False, RESOLVERS["deny"]
    return None
