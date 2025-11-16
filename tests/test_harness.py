"""Matrix runner and report generator (spec 18)."""

from __future__ import annotations

import json

import pytest
from harness import report, run_matrix

from doorman.config import Settings
from doorman.guard.classifier import NullGuard
from tests.fakes import BenignClient, CompliantClient, FakeClient, ResumeClient, text


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


@pytest.fixture
def benign_corpus(tmp_path):
    """Three benign items built with a scripted generator: one ordinary, one
    hard negative, one DOCX."""
    from corpus.benign import generate

    out = tmp_path / "benign"
    specs = [s for s in generate.load_specs() if s.id in ("BEN-001", "BEN-084", "BEN-089")]
    for spec in specs:
        generate.build_one(ResumeClient(), spec, model="fake", out_dir=out)
    return out, [s.id for s in specs]


@pytest.fixture
def benign_sweep(tmp_path, benign_corpus):
    out, ids = benign_corpus
    results = tmp_path / "benign.jsonl"
    run_matrix.run(
        configs=["none", "full"], corpus="benign", repeats=1, only=ids,
        client_factory=BenignClient, results_path=results,
        benign_dir=out, runs_root=tmp_path / "runs", settings=Settings(),
        # Spec 19: CI never downloads the classifier. `full` here means every
        # layer except the model behind CLS-*.
        guard=NullGuard(),
    )
    return results


class TestBenignMatrix:
    def test_one_row_per_config_and_item(self, benign_sweep):
        assert len(rows(benign_sweep)) == 6

    def test_rows_carry_the_false_positive_fields(self, benign_sweep):
        for row in rows(benign_sweep):
            for key in ("corpus", "denied", "aborted", "taint", "score", "decision",
                        "hard_negative"):
                assert key in row, key
            assert row["corpus"] == "benign"

    def test_no_oracle_fields_on_a_benign_row(self, benign_sweep):
        """Nothing is being attacked, so `reached` and `executed` would be
        meaningless columns that a reader could still average."""
        for row in rows(benign_sweep):
            assert "reached" not in row
            assert "executed" not in row

    def test_an_ordinary_applicant_is_neither_denied_nor_aborted(self, benign_sweep):
        for row in rows(benign_sweep):
            assert row["denied"] is False, row
            assert row["aborted"] is False, row

    def test_each_item_is_screened_under_its_own_name(self, tmp_path, benign_corpus):
        """The ATS record has to be the applicant in the document, or every
        benign run looks like a candidate swap."""
        from corpus.benign import generate
        out, _ = benign_corpus
        spec = next(s for s in generate.load_specs() if s.id == "BEN-084")
        row = run_matrix.run_benign_cell(
            BenignClient(), Settings(), spec, "full", 1,
            benign_dir=out, runs_root=tmp_path / "r2", guard=NullGuard(),
        )
        assert row["error"] is None if "error" in row else True
        assert row["score"] is not None

    def test_benign_and_attack_rows_do_not_collide_when_resuming(
        self, tmp_path, benign_corpus
    ):
        """The resume key includes the corpus. Without it, an attack and a benign
        item that shared an id would silently skip each other."""
        out, ids = benign_corpus
        results = tmp_path / "mixed.jsonl"
        run_matrix.run(configs=["none"], corpus="attacks", only=["DIR-001"],
                       client_factory=CompliantClient, results_path=results,
                       runs_root=tmp_path / "a", settings=Settings())
        run_matrix.run(configs=["none"], corpus="benign", only=ids,
                       client_factory=BenignClient, results_path=results,
                       benign_dir=out, runs_root=tmp_path / "b", settings=Settings())
        corpora = [r.get("corpus") for r in rows(results)]
        assert corpora.count("attacks") == 1
        assert corpora.count("benign") == 3

    def test_an_interrupted_sweep_resumes_where_it_stopped(self, tmp_path, benign_corpus):
        """Resumability is not optional at 1,200 runs. Half the sweep is written,
        then the same call finishes the rest without repeating any of it."""
        out, ids = benign_corpus
        results = tmp_path / "partial.jsonl"
        run_matrix.run(configs=["none"], corpus="benign", only=ids[:1],
                       client_factory=BenignClient, results_path=results,
                       benign_dir=out, runs_root=tmp_path / "p1", settings=Settings())
        first = [r["run_id"] for r in rows(results)]

        run_matrix.run(configs=["none"], corpus="benign", only=ids,
                       client_factory=BenignClient, results_path=results,
                       benign_dir=out, runs_root=tmp_path / "p2", settings=Settings())
        after = rows(results)
        assert len(after) == 3
        assert [r["run_id"] for r in after][: len(first)] == first

    def test_an_unknown_corpus_is_rejected(self):
        with pytest.raises(ValueError, match="unknown corpus"):
            run_matrix.run(configs=["none"], corpus="dubious")


class TestConcurrency:
    def test_four_workers_produce_the_same_rows(self, tmp_path, benign_corpus):
        out, ids = benign_corpus
        results = tmp_path / "c.jsonl"
        run_matrix.run(
            configs=["none", "full"], corpus="benign", only=ids, concurrency=4,
            client_factory=BenignClient, results_path=results,
            benign_dir=out, runs_root=tmp_path / "runs", settings=Settings(),
            guard=NullGuard(),
        )
        data = rows(results)
        assert len(data) == 6
        assert len({(r["config"], r["item_id"]) for r in data}) == 6

    def test_concurrency_is_capped(self, tmp_path, benign_corpus):
        """Spec 18 caps it at 4. A caller asking for 32 gets 4, not 32."""
        out, ids = benign_corpus
        results = tmp_path / "cap.jsonl"
        run_matrix.run(
            configs=["none"], corpus="benign", only=ids, concurrency=32,
            client_factory=BenignClient, results_path=results,
            benign_dir=out, runs_root=tmp_path / "runs", settings=Settings(),
        )
        assert len(rows(results)) == 3
        assert run_matrix.MAX_CONCURRENCY == 4


class TestPricing:
    def test_cost_is_computed_from_the_pricing_file(self, tmp_path):
        from harness import pricing

        path = tmp_path / "pricing.yaml"
        path.write_text("model-a:\n  input: 2.0\n  output: 10.0\n")
        assert pricing.cost_usd("model-a", 1_000_000, 100_000, path) == 3.0

    def test_an_unpriced_model_reports_unknown_not_free(self, tmp_path):
        from harness import pricing

        path = tmp_path / "pricing.yaml"
        path.write_text("model-b:\n  input: null\n  output: null\n")
        assert pricing.cost_usd("model-b", 1000, 100, path) is None

    def test_the_shipped_pricing_file_covers_both_pinned_models(self):
        from harness import pricing

        settings = Settings()
        assert pricing.rate(settings.agent_model) is not None
        assert pricing.rate(settings.reader_model) is not None

    def test_a_row_carries_a_cost(self, benign_sweep):
        for row in rows(benign_sweep):
            assert row["cost_usd"] is not None and row["cost_usd"] > 0


class TestFalsePositiveReport:
    def test_the_fpr_table_is_present(self, tmp_path, benign_sweep):
        report.build(results_path=benign_sweep, report_path=tmp_path / "R.md",
                     summary_path=tmp_path / "s.json")
        body = (tmp_path / "R.md").read_text()
        assert "False positives on the benign corpus" in body
        for column in ("FP_hard", "FP_soft", "score_drift", "decision agreement"):
            assert column in body

    def test_summary_carries_the_fpr_numbers(self, tmp_path, benign_sweep):
        report.build(results_path=benign_sweep, report_path=tmp_path / "R.md",
                     summary_path=tmp_path / "s.json")
        summary = json.loads((tmp_path / "s.json").read_text())
        assert summary["benign_runs"] == 6
        assert summary["fpr"]["full"]["n"] == 3
        assert summary["fpr"]["full"]["fp_hard"] == 0

    def test_score_drift_is_measured_against_the_undefended_run(self, tmp_path,
                                                               benign_corpus):
        """A defence that quietly re-scores every applicant has a cost even when
        it blocks nothing."""
        out, ids = benign_corpus
        results = tmp_path / "drift.jsonl"
        run_matrix.run(configs=["none"], corpus="benign", only=ids,
                       client_factory=lambda: BenignClient(score=60),
                       results_path=results, benign_dir=out,
                       runs_root=tmp_path / "a", settings=Settings())
        run_matrix.run(configs=["full"], corpus="benign", only=ids,
                       client_factory=lambda: BenignClient(score=48),
                       results_path=results, benign_dir=out,
                       runs_root=tmp_path / "b", settings=Settings(),
                       guard=NullGuard())
        report.build(results_path=results, report_path=tmp_path / "R.md",
                     summary_path=tmp_path / "s.json")
        summary = json.loads((tmp_path / "s.json").read_text())
        assert summary["fpr"]["full"]["score_drift"] == 12.0
        assert summary["fpr"]["full"]["decision_agreement_pct"] == 100.0

    def test_a_downgraded_applicant_is_named_not_just_counted(self, tmp_path,
                                                             benign_corpus):
        """A rate alone cannot be checked. The hard negatives exist to be
        inspected by name."""
        out, ids = benign_corpus
        results = tmp_path / "named.jsonl"
        run_matrix.run(configs=["full"], corpus="benign", only=ids,
                       client_factory=BenignClient, results_path=results,
                       benign_dir=out, runs_root=tmp_path / "runs",
                       settings=Settings(), guard=NullGuard())
        data = rows(results)
        for row in data:
            row["taint"] = "suspicious"
        results.write_text("\n".join(json.dumps(r) for r in data) + "\n")
        report.build(results_path=results, report_path=tmp_path / "R.md",
                     summary_path=tmp_path / "s.json")
        body = (tmp_path / "R.md").read_text()
        assert "BEN-084" in body
        assert "Ignore Ltd." in body

    def test_the_appendix_carries_per_attack_detail(self, tmp_path, sweep):
        report.build(results_path=sweep, report_path=tmp_path / "R.md",
                     summary_path=tmp_path / "s.json")
        body = (tmp_path / "R.md").read_text()
        assert "<details><summary>Per-attack rows</summary>" in body
        assert "DIR-001" in body

    def test_the_header_records_the_classifier_and_thresholds(self, tmp_path, sweep):
        report.build(results_path=sweep, report_path=tmp_path / "R.md",
                     summary_path=tmp_path / "s.json")
        body = (tmp_path / "R.md").read_text()
        assert "Classifier:" in body
        assert "Repeats:" in body
        assert "hidden font" in body


class TestErroredRunsAreNotSecurityOutcomes:
    """A run that died on a rate limit is not an attack the defences stopped and
    not an applicant they refused. Counting it as either invents a number."""

    def _write(self, path, rows_):
        path.write_text("\n".join(json.dumps(r) for r in rows_) + "\n")

    def test_an_errored_attack_does_not_lower_the_reported_asr(self, tmp_path):
        results = tmp_path / "r.jsonl"
        self._write(results, [
            {"config": "full", "corpus": "attacks", "item_id": "A1", "family": "direct",
             "rep": 1, "reached": True, "executed": True},
            {"config": "full", "corpus": "attacks", "item_id": "A2", "family": "direct",
             "rep": 1, "reached": False, "executed": False,
             "error": "APITimeoutError: timed out"},
        ])
        report.build(results_path=results, report_path=tmp_path / "R.md",
                     summary_path=tmp_path / "s.json")
        summary = json.loads((tmp_path / "s.json").read_text())
        overall = summary["asr"]["all attacks"]["full"]
        assert overall["n"] == 1
        assert overall["executed_pct"] == 100.0
        assert summary["errored_runs_excluded"] == 1

    def test_an_errored_benign_run_does_not_inflate_the_false_positive_rate(self, tmp_path):
        results = tmp_path / "r.jsonl"
        self._write(results, [
            {"config": "full", "corpus": "benign", "item_id": "BEN-001", "rep": 1,
             "denied": False, "aborted": False, "taint": "clean", "score": 60,
             "decision": "hold", "hard_negative": False},
            {"config": "full", "corpus": "benign", "item_id": "BEN-002", "rep": 1,
             "denied": False, "aborted": True, "hard_negative": False,
             "error": "APIConnectionError: connection reset"},
        ])
        report.build(results_path=results, report_path=tmp_path / "R.md",
                     summary_path=tmp_path / "s.json")
        fpr = json.loads((tmp_path / "s.json").read_text())["fpr"]["full"]
        assert fpr["n"] == 1
        assert fpr["fp_hard"] == 0

    def test_a_genuine_abort_still_counts_as_a_hard_false_positive(self, tmp_path):
        """Only an `error` is excluded. A run the defences aborted - a reader
        failure, no decision recorded - is exactly what FP_hard is for."""
        results = tmp_path / "r.jsonl"
        self._write(results, [
            {"config": "full", "corpus": "benign", "item_id": "BEN-001", "rep": 1,
             "denied": False, "aborted": True, "taint": "clean", "score": None,
             "decision": None, "hard_negative": False},
        ])
        report.build(results_path=results, report_path=tmp_path / "R.md",
                     summary_path=tmp_path / "s.json")
        fpr = json.loads((tmp_path / "s.json").read_text())["fpr"]["full"]
        assert fpr["n"] == 1 and fpr["fp_hard"] == 1

    def test_an_errored_run_is_still_listed(self, tmp_path):
        """Excluded from the rates, never from the record."""
        results = tmp_path / "r.jsonl"
        self._write(results, [
            {"config": "full", "corpus": "attacks", "item_id": "A2", "family": "direct",
             "rep": 1, "reached": False, "executed": False, "error": "RuntimeError: boom"},
        ])
        report.build(results_path=results, report_path=tmp_path / "R.md",
                     summary_path=tmp_path / "s.json")
        body = (tmp_path / "R.md").read_text()
        assert "RuntimeError: boom" in body
        assert "excluded from every rate" in body

    def test_two_aborted_runs_are_not_two_runs_that_agreed(self, tmp_path):
        """`None == None` would let a config that broke every applicant report
        perfect decision agreement with the baseline."""
        results = tmp_path / "r.jsonl"
        self._write(results, [
            {"config": "none", "corpus": "benign", "item_id": "BEN-001", "rep": 1,
             "denied": False, "aborted": False, "taint": "clean", "score": 60,
             "decision": "hold", "hard_negative": False},
            {"config": "full", "corpus": "benign", "item_id": "BEN-001", "rep": 1,
             "denied": False, "aborted": True, "taint": "clean", "score": None,
             "decision": None, "hard_negative": False},
        ])
        report.build(results_path=results, report_path=tmp_path / "R.md",
                     summary_path=tmp_path / "s.json")
        fpr = json.loads((tmp_path / "s.json").read_text())["fpr"]["full"]
        assert fpr["decision_agreement_pct"] is None
        assert fpr["paired_with_baseline"] == 0

    def test_a_benign_error_row_carries_no_oracle_verdict(self, tmp_path, benign_corpus):
        """`reached` and `executed` are attack-corpus columns. A benign row that
        had them could be averaged into an attack table."""
        from corpus.benign import generate

        class Exploding:
            def __init__(self):
                self.messages = self

            def create(self, **kwargs):
                raise RuntimeError("model exploded")

        out, _ = benign_corpus
        spec = next(s for s in generate.load_specs() if s.id == "BEN-001")
        row = run_matrix.run_benign_cell(
            Exploding(), Settings(), spec, "none", 1,
            benign_dir=out, runs_root=tmp_path / "e",
        )
        assert "model exploded" in row["error"]
        assert "reached" not in row and "executed" not in row
        assert row["aborted"] is True


class TestReadmeResults:
    """The README's results section is generated from summary.json (spec 20, M5)."""

    def test_build_fills_the_block_when_given_a_readme(self, tmp_path, benign_sweep):
        readme = tmp_path / "README.md"
        readme.write_text(
            f"# Doorman\n\n{report.RESULTS_START}\nstale\n{report.RESULTS_END}\n\n## Next\n"
        )
        report.build(results_path=benign_sweep, report_path=tmp_path / "R.md",
                     summary_path=tmp_path / "s.json", readme_path=readme)
        body = readme.read_text()
        assert "stale" not in body
        assert "False positives" in body
        assert body.startswith("# Doorman") and body.rstrip().endswith("## Next")

    def test_it_says_so_rather_than_inventing_numbers(self, tmp_path):
        readme = tmp_path / "README.md"
        readme.write_text(f"{report.RESULTS_START}\n{report.RESULTS_END}\n")
        report.update_readme({"runs": 0}, readme_path=readme)
        assert "No matrix has been run yet" in readme.read_text()

    def test_the_hard_negative_count_is_derived_not_asserted(self, tmp_path,
                                                             benign_sweep):
        """A sentence naming 100 applicants would read as true above a table
        built from three."""
        report.build(results_path=benign_sweep, report_path=tmp_path / "R.md",
                     summary_path=tmp_path / "s.json")
        summary = json.loads((tmp_path / "s.json").read_text())
        block = "\n".join(report.readme_tables(summary))
        expected = max(e["hard_negative_n"] for e in summary["fpr"].values())
        assert "100 applicants" not in block
        assert f"{expected} of them hard negatives" in block
        assert expected == 2, "the sweep covers BEN-084 and BEN-089"

    def test_a_readme_without_markers_is_left_alone(self, tmp_path):
        readme = tmp_path / "README.md"
        readme.write_text("# Doorman\n\nno markers here\n")
        assert report.update_readme({"runs": 0}, readme_path=readme) is None
        assert readme.read_text() == "# Doorman\n\nno markers here\n"


    def test_build_leaves_the_readme_alone_unless_asked(self, tmp_path, benign_sweep):
        """The default is no side effect. Only `doorman report` opts in."""
        readme = tmp_path / "README.md"
        readme.write_text(f"{report.RESULTS_START}\nuntouched\n{report.RESULTS_END}\n")
        report.build(results_path=benign_sweep, report_path=tmp_path / "R.md",
                     summary_path=tmp_path / "s.json")
        assert "untouched" in readme.read_text()
