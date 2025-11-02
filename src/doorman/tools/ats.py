"""Mock ATS backed by SQLite (spec 13).

Seeded fresh from a YAML fixture for every run, so no run can inherit state - or
a poisoned note - from the one before it.

Trust boundary (spec 2): `candidate_id`, `full_name`, `email` and `status` are
recruiter-set and trusted. `notes` is free text of unknown provenance and is
treated as untrusted everywhere it is read.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from doorman.models import ATSRecord

SCHEMA = """
CREATE TABLE IF NOT EXISTS candidates (
  candidate_id TEXT PRIMARY KEY, job_id TEXT NOT NULL,
  full_name TEXT NOT NULL, email TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('new','screening','hold','advance','reject')),
  notes TEXT NOT NULL DEFAULT '', applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scores (
  id INTEGER PRIMARY KEY, run_id TEXT, candidate_id TEXT NOT NULL,
  score INTEGER NOT NULL, rationale TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decisions (
  id INTEGER PRIMARY KEY, run_id TEXT, candidate_id TEXT NOT NULL,
  status TEXT NOT NULL, rationale TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_actions (
  id INTEGER PRIMARY KEY, run_id TEXT, trace_id TEXT, candidate_id TEXT,
  tool TEXT, args_json TEXT, rule_id TEXT, created_at TEXT,
  status TEXT CHECK(status IN ('pending','approved','rejected')),
  resolved_at TEXT, resolver TEXT
);
"""

# Notes the ATS writes itself. The hardened `ats_update` picks an id; it has no
# free-text note parameter (spec 11.4).
NOTE_TEMPLATES = {
    "scored": "Automated screen recorded a score for this application.",
    "advanced": "Automated screen recommended advancing this application.",
    "held": "Automated screen placed this application on hold.",
    "rejected": "Automated screen recommended rejecting this application.",
}


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class ATS:
    path: Path

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    # --- setup ---------------------------------------------------------------

    def create_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def seed(self, seed_path: Path) -> None:
        data = yaml.safe_load(Path(seed_path).read_text(encoding="utf-8")) or {}
        rows = data.get("candidates", [])
        self.create_schema()
        with self._connect() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO candidates "
                "(candidate_id, job_id, full_name, email, status, notes, applied_at) "
                "VALUES (:candidate_id, :job_id, :full_name, :email, :status, "
                ":notes, :applied_at)",
                [{**row, "notes": row.get("notes", "")} for row in rows],
            )

    @classmethod
    def seeded(cls, path: Path, seed_path: Path) -> ATS:
        ats = cls(path)
        ats.seed(seed_path)
        return ats

    # --- reads ---------------------------------------------------------------

    def get(self, candidate_id: str) -> ATSRecord:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM candidates WHERE candidate_id = ?", (candidate_id,)
            ).fetchone()
        if row is None:
            raise KeyError(f"no ATS record for {candidate_id!r}")
        return ATSRecord(**dict(row))

    def all_candidates(self) -> list[ATSRecord]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM candidates ORDER BY candidate_id").fetchall()
        return [ATSRecord(**dict(row)) for row in rows]

    def other_candidate_ids(self, candidate_id: str) -> set[str]:
        """Populates `RunContext.batch_candidate_ids` for OUT-004."""
        return {r.candidate_id for r in self.all_candidates()} - {candidate_id}

    def scores(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        return self._rows("scores", candidate_id)

    def decisions(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        return self._rows("decisions", candidate_id)

    def pending_actions(self, run_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM pending_actions"
        params: tuple[Any, ...] = ()
        if run_id is not None:
            query += " WHERE run_id = ?"
            params = (run_id,)
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(query + " ORDER BY id", params).fetchall()]

    def _rows(self, table: str, candidate_id: str | None) -> list[dict[str, Any]]:
        query = f"SELECT * FROM {table}"  # noqa: S608 - table name is a literal above
        params: tuple[Any, ...] = ()
        if candidate_id is not None:
            query += " WHERE candidate_id = ?"
            params = (candidate_id,)
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(query + " ORDER BY id", params).fetchall()]

    # --- writes --------------------------------------------------------------

    def record_score(
        self, *, run_id: str, candidate_id: str, score: int, rationale: str
    ) -> dict[str, Any]:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO scores (run_id, candidate_id, score, rationale, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (run_id, candidate_id, score, rationale, _now()),
            )
        return {"candidate_id": candidate_id, "score": score}

    def record_decision(
        self, *, run_id: str, candidate_id: str, status: str, rationale: str
    ) -> dict[str, Any]:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO decisions (run_id, candidate_id, status, rationale, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (run_id, candidate_id, status, rationale, _now()),
            )
        return {"candidate_id": candidate_id, "status": status}

    def update_status(
        self, *, candidate_id: str, status: str, note: str | None = None
    ) -> dict[str, Any]:
        """Set status and optionally append a note. Returns the effect for the log."""
        before = self.get(candidate_id)
        notes = before.notes
        if note:
            notes = f"{notes}\n{note}".strip()
        with self._connect() as conn:
            conn.execute(
                "UPDATE candidates SET status = ?, notes = ? WHERE candidate_id = ?",
                (status, notes, candidate_id),
            )
        return {
            "candidate_id": candidate_id,
            "status_from": before.status,
            "status_to": status,
            "note_appended": bool(note),
        }
