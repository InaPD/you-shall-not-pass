"""Matrix runner and report generator (spec 18)."""

from __future__ import annotations

import json

import pytest
from harness import report, run_matrix

from doorman.config import Settings
from tests.fakes import CompliantClient, FakeClient, text


@pytest.fixture
def sweep(tmp_path):
    """A small real sweep: two configs over three attacks, scripted client."""
    results = tmp_path / "results.jsonl"
    run_matrix.run(
        configs=["none", "isolation_only"], repeats=1,
        only=["DIR-001", "HID-001", "META-003"],
        client_factory=CompliantClient, results_path=results,
        runs_root=tmp_path / "runs", settings=Settings(),
    )
    return results


def rows(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


class TestMatrix:
    def test_writes_one_row_per_cell(self, sweep):
        assert len(rows(sweep)) == 6

    def test_rows_carry_the_reporting_fields(self, sweep):
        for row in rows(sweep):
            for key in ("config", "item_id", "family", "rep", "reached", "executed"):
                assert key in row, key

    def test_a_fresh_client_per_run(self, sweep):
        """Otherwise a stateful fake is exhausted after the first cell and every
        later run silently does nothing."""
        scored = [r for r in rows(sweep) if r.get("score") is not None]
        assert len(scored) == 6

    def test_each_run_starts_from_a_clean_ats(self, sweep):
        """Spec 13: a poisoned or advanced record must not leak into the next run."""
        assert all(r.get("error") is None for r in rows(sweep))

    def test_resumable(self, tmp_path, sweep):
        before = len(rows(sweep))
        run_matrix.run(
            configs=["none", "isolation_only"], repeats=1,
            only=["DIR-001", "HID-001", "META-003"],
            client_factory=CompliantClient, results_path=sweep,
            runs_root=tmp_path / "runs2", settings=Settings(),
        )
        assert len(rows(sweep)) == before  # nothing re-run

    def test_only_filters_by_family(self, tmp_path):
        results = tmp_path / "r.jsonl"
        run_matrix.run(configs=["none"], only=["metadata"],
                       client_factory=CompliantClient, results_path=results,
                       runs_root=tmp_path / "runs", settings=Settings())
        assert {r["family"] for r in rows(results)} == {"metadata"}

    def test_a_crashing_run_becomes_an_error_row_not_a_gap(self, tmp_path):
        class Exploding:
            def __init__(self):
                self.messages = self

            def create(self, **kwargs):
                raise RuntimeError("model exploded")

        results = tmp_path / "r.jsonl"
        run_matrix.run(configs=["none"], only=["DIR-001"],
                       client_factory=Exploding, results_path=results,
                       runs_root=tmp_path / "runs", settings=Settings())
        (row,) = rows(results)
        assert "model exploded" in row["error"]
        assert row["executed"] is False


class TestReport:
    def test_writes_report_and_summary(self, tmp_path, sweep):
        path = report.build(results_path=sweep, report_path=tmp_path / "REPORT.md",
                            summary_path=tmp_path / "summary.json")
        assert path.is_file()
        assert (tmp_path / "summary.json").is_file()

    def test_report_has_the_required_sections(self, tmp_path, sweep):
        report.build(results_path=sweep, report_path=tmp_path / "REPORT.md",
                     summary_path=tmp_path / "summary.json")
        body = (tmp_path / "REPORT.md").read_text()
        for heading in ("Attack success rate by family", "Rules fired", "Ablation"):
            assert heading in body

    def test_cells_carry_n(self, tmp_path, sweep):
        report.build(results_path=sweep, report_path=tmp_path / "REPORT.md",
                     summary_path=tmp_path / "summary.json")
        assert "n=" in (tmp_path / "REPORT.md").read_text()

    def test_summary_json_matches_the_table(self, tmp_path, sweep):
        report.build(results_path=sweep, report_path=tmp_path / "REPORT.md",
                     summary_path=tmp_path / "summary.json")
        summary = json.loads((tmp_path / "summary.json").read_text())
        assert summary["runs"] == 6
        assert set(summary["configs"]) == {"none", "isolation_only"}
        assert summary["asr"]["all attacks"]["none"]["n"] == 3

    def test_models_are_recorded(self, tmp_path, sweep):
        report.build(results_path=sweep, report_path=tmp_path / "REPORT.md",
                     summary_path=tmp_path / "summary.json")
        body = (tmp_path / "REPORT.md").read_text()
        assert Settings().agent_model in body
        assert Settings().reader_model in body

    def test_empty_results_do_not_crash(self, tmp_path):
        empty = tmp_path / "empty.jsonl"
        empty.write_text("")
        report.build(results_path=empty, report_path=tmp_path / "R.md",
                     summary_path=tmp_path / "s.json")
        assert (tmp_path / "R.md").is_file()

    def test_the_reading_note_about_reached_is_present(self, tmp_path, sweep):
        """The reached% column is easy to misread; the caveat must ship with it."""
        report.build(results_path=sweep, report_path=tmp_path / "REPORT.md",
                     summary_path=tmp_path / "summary.json")
        assert "taint gate" in (tmp_path / "REPORT.md").read_text()


class TestIsolationBeatsBaseline:
    def test_hardened_tools_reduce_executed_attacks(self, tmp_path):
        """The M2 gate: isolation_only must do better than none against a model
        that has been fully persuaded."""
        results = tmp_path / "r.jsonl"
        run_matrix.run(
            configs=["none", "isolation_only"], repeats=1,
            client_factory=CompliantClient, results_path=results,
            runs_root=tmp_path / "runs", settings=Settings(),
        )
        data = rows(results)
        none_hits = sum(1 for r in data if r["config"] == "none" and r["executed"])
        iso_hits = sum(1 for r in data if r["config"] == "isolation_only" and r["executed"])
        assert iso_hits < none_hits, f"none={none_hits} isolation_only={iso_hits}"

    def test_a_silent_model_lands_nothing(self, tmp_path):
        results = tmp_path / "r.jsonl"
        run_matrix.run(configs=["none"], only=["DIR-001"],
                       client_factory=lambda: FakeClient(text("No.")),
                       results_path=results, runs_root=tmp_path / "runs",
                       settings=Settings())
        assert rows(results)[0]["executed"] is False
