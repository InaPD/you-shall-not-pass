"""Mock tools (spec 13). Nothing here may touch the network."""

from __future__ import annotations

import pytest

from doorman.config import CONFIG_DIR
from doorman.tools import web
from doorman.tools.ats import ATS
from doorman.tools.email import TEMPLATES, Outbox

SEED = CONFIG_DIR.parent / "corpus" / "fixtures" / "ats_seed.yaml"


@pytest.fixture
def ats(tmp_path) -> ATS:
    return ATS.seeded(tmp_path / "ats.db", SEED)


@pytest.fixture
def outbox(tmp_path) -> Outbox:
    return Outbox(tmp_path / "outbox.jsonl")


class TestOutbox:
    def test_send_appends_a_row(self, outbox):
        outbox.send(run_id="r1", candidate_id="C001", to="a@example.com",
                    subject="Hi", body="Body")
        (row,) = outbox.rows()
        assert row["to"] == "a@example.com"
        assert row["run_id"] == "r1"

    def test_rows_is_empty_before_anything_is_sent(self, outbox):
        assert outbox.rows() == []

    def test_send_template_uses_the_trusted_name_not_the_model(self, outbox):
        outbox.send_template(run_id="r1", candidate_id="C001", to="a@example.com",
                             full_name="Jordan Avery", template_id="reject_polite")
        (row,) = outbox.rows()
        assert "Jordan Avery" in row["body"]
        assert row["subject"] == TEMPLATES["reject_polite"][0]

    def test_personal_note_is_appended_to_the_rendered_body(self, outbox):
        outbox.send_template(run_id="r1", candidate_id="C001", to="a@example.com",
                             full_name="Jordan Avery", template_id="hold_update",
                             personal_note="Following up next week.")
        (row,) = outbox.rows()
        assert "Following up next week." in row["body"]
        assert row["personal_note"] == "Following up next week."

    def test_unknown_template_is_rejected(self, outbox):
        with pytest.raises(KeyError):
            outbox.send_template(run_id="r1", candidate_id="C001", to="a@example.com",
                                 full_name="X", template_id="wire_transfer")


class TestATS:
    def test_seed_loads_every_candidate(self, ats):
        assert len(ats.all_candidates()) == 6

    def test_get_returns_a_typed_record(self, ats):
        record = ats.get("C001")
        assert record.full_name == "Jordan Avery"
        assert record.status == "new"

    def test_unknown_candidate_raises(self, ats):
        with pytest.raises(KeyError):
            ats.get("C999")

    def test_other_candidate_ids_excludes_the_subject(self, ats):
        others = ats.other_candidate_ids("C001")
        assert "C001" not in others
        assert {"C002", "C003", "C004", "C005", "C006"} == others

    def test_update_status_reports_the_transition(self, ats):
        effect = ats.update_status(candidate_id="C001", status="advance")
        assert effect == {
            "candidate_id": "C001", "status_from": "new",
            "status_to": "advance", "note_appended": False,
        }
        assert ats.get("C001").status == "advance"

    def test_update_status_appends_rather_than_replacing_notes(self, ats):
        before = ats.get("C001").notes
        ats.update_status(candidate_id="C001", status="hold", note="Second pass.")
        after = ats.get("C001").notes
        assert before in after
        assert "Second pass." in after

    def test_invalid_status_is_rejected_by_the_schema(self, ats):
        import sqlite3

        with pytest.raises(sqlite3.IntegrityError):
            ats.update_status(candidate_id="C001", status="hired")

    def test_scores_and_decisions_are_recorded(self, ats):
        ats.record_score(run_id="r1", candidate_id="C001", score=41, rationale="junior")
        ats.record_decision(run_id="r1", candidate_id="C001", status="reject", rationale="no")
        assert ats.scores("C001")[0]["score"] == 41
        assert ats.decisions("C001")[0]["status"] == "reject"

    def test_seeding_is_idempotent_so_runs_start_clean(self, tmp_path):
        path = tmp_path / "a.db"
        first = ATS.seeded(path, SEED)
        first.update_status(candidate_id="C001", status="advance")
        second = ATS.seeded(path, SEED)
        assert second.get("C001").status == "new"

    def test_pending_actions_table_exists_for_phase_3(self, ats):
        assert ats.pending_actions() == []


class TestWebFetch:
    def test_resolves_a_fixture_page(self):
        result = web.fetch("https://portfolio.example/jordan-avery")
        assert "Jordan Avery" in result["text"]
        assert "error" not in result

    def test_strips_markup(self):
        result = web.fetch("https://portfolio.example/jordan-avery")
        assert "<h1>" not in result["text"]

    @pytest.mark.parametrize(
        "url",
        [
            "https://evil.example/jordan-avery",
            "https://portfolio.example.evil.com/jordan-avery",
            "http://portfolio.example/../../etc/passwd",
            "https://portfolio.example/no-such-slug",
            "file:///etc/passwd",
            "ftp://portfolio.example/x",
            "not a url at all",
            "https://portfolio.example/",
        ],
    )
    def test_refuses_everything_else(self, url):
        assert web.fetch(url) == {"error": "unresolvable"}

    def test_traversal_cannot_escape_the_fixture_directory(self, tmp_path):
        secret = tmp_path / "secret.html"
        secret.write_text("<p>top secret</p>")
        assert web.fetch("https://portfolio.example/%2e%2e%2fsecret") == {
            "error": "unresolvable"
        }
