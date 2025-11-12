"""The phased flow (spec 12.3).

The properties under test are structural: the privileged agent never sees the
raw document, each phase is offered only its own tools, and phase transitions
are decided by code.
"""

from __future__ import annotations

import json

import pytest
from corpus.attacks import build

from doorman import config
from doorman.agent import orchestrator
from doorman.config import Settings
from doorman.guard.classifier import NullGuard
from doorman.models import Taint
from doorman.policy import phases
from doorman.tools.ats import ATS
from doorman.tools.email import Outbox
from tests.fakes import DEFAULT_PROFILE, CompliantClient, FakeClient, text, tool_use

SEED = config.CONFIG_DIR.parent / "corpus" / "fixtures" / "ats_seed.yaml"


@pytest.fixture(scope="module")
def attack_files(tmp_path_factory):
    out = tmp_path_factory.mktemp("phased-attacks")
    return {spec.id: path for spec, path in build.build_all(out_dir=out)}


def run(client, tmp_path, doc_path, *, preset="full", candidate="C001",
        guard=None, approval="auto"):
    """The guard is always injected. `build_guard` deliberately has no fallback:
    a `full` run without the extra installed must fail loudly rather than quietly
    report a classifier it never had."""
    return orchestrator.run_candidate(
        client, Settings(), config.preset(preset),
        doc_path=doc_path, candidate_id=candidate, job_id="J001",
        run_id="phased-test", runs_root=tmp_path, ats_seed=SEED,
        guard=guard or NullGuard(), approval=approval,
    )


def events(result) -> list[dict]:
    return [
        json.loads(line)
        for line in result.events_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def good_run() -> FakeClient:
    return FakeClient(
        tool_use(("emit_profile", DEFAULT_PROFILE)),
        tool_use(("score_candidate", {"score": 34, "rationale": "Junior."})),
        tool_use(("propose_decision", {"status": "reject", "rationale": "Below bar."})),
        tool_use(("send_email", {"template_id": "reject_polite"})),
        tool_use(("ats_update", {"status": "reject", "note_template_id": "rejected"})),
    )


class TestPhaseStructure:
    def test_each_phase_is_a_separate_call(self, tmp_path, attack_files):
        client = good_run()
        run(client, tmp_path, attack_files["DIR-001"], preset="isolation_only")
        assert len(client.calls) == 5

    def test_each_phase_is_offered_only_its_own_tools(self, tmp_path, attack_files):
        client = good_run()
        run(client, tmp_path, attack_files["DIR-001"], preset="isolation_only")
        offered = [tuple(t["name"] for t in call["tools"]) for call in client.calls]
        assert offered[0] == ("emit_profile",)
        assert set(offered[1]) == set(phases.allowed(orchestrator.Phase.SCORE))
        assert set(offered[2]) == set(phases.allowed(orchestrator.Phase.DECIDE))
        assert offered[3] == ("send_email",)
        assert offered[4] == ("ats_update",)

    def test_phases_do_not_share_conversation_history(self, tmp_path, attack_files):
        """Spec 12.3: each phase builds a fresh messages list."""
        client = good_run()
        run(client, tmp_path, attack_files["DIR-001"], preset="isolation_only")
        for call in client.calls[1:]:
            assert len(call["messages"]) == 1
            assert call["messages"][0]["role"] == "user"

    def test_the_reader_runs_on_the_reader_model_and_the_agent_on_the_agent_model(
        self, tmp_path, attack_files
    ):
        client = good_run()
        run(client, tmp_path, attack_files["DIR-001"], preset="isolation_only")
        settings = Settings()
        assert client.calls[0]["model"] == settings.reader_model
        assert {c["model"] for c in client.calls[1:]} == {settings.agent_model}


class TestAgentNeverSeesRawDocument:
    """Spec 21.5 - the property the whole isolation claim rests on."""

    def test_hidden_text_never_reaches_the_privileged_agent(self, tmp_path, attack_files):
        client = good_run()
        run(client, tmp_path, attack_files["HID-001"])
        for call in client.calls[1:]:  # skip the reader
            assert "HR-22" not in json.dumps(call, default=str)

    def test_metadata_never_reaches_the_privileged_agent(self, tmp_path, attack_files):
        client = good_run()
        run(client, tmp_path, attack_files["META-003"])
        for call in client.calls[1:]:
            blob = json.dumps(call, default=str)
            assert "HR-22" not in blob
            assert "pdf.xmp" not in blob

    def test_the_agent_sees_the_typed_profile_instead(self, tmp_path, attack_files):
        client = good_run()
        run(client, tmp_path, attack_files["HID-001"], preset="isolation_only")
        assert "CANDIDATE PROFILE" in client.calls[1]["system"]

    def test_no_prompt_mentions_a_rule_id(self, tmp_path, attack_files):
        """Spec 21.12."""
        import re

        client = good_run()
        run(client, tmp_path, attack_files["DIR-001"])
        for call in client.calls:
            assert not re.search(r"\b(ING|CLS|POL|OUT|APR)-\d{3}\b", call["system"])


class TestTaintGate:
    def test_a_suspicious_document_never_reaches_communicate(self, tmp_path,
                                                             attack_files):
        client = good_run()
        result = run(client, tmp_path, attack_files["HID-001"])  # full: ING rules on
        assert result.taint is Taint.SUSPICIOUS
        assert result.status == "review"
        offered = [tuple(t["name"] for t in call["tools"]) for call in client.calls]
        assert ("send_email",) not in offered
        assert ("ats_update",) not in offered

    def test_it_still_scores_and_decides(self, tmp_path, attack_files):
        """Spec 11.2: the recruiter still receives a recommendation."""
        result = run(good_run(), tmp_path, attack_files["HID-001"])
        assert result.score == 34
        assert result.decision == "reject"

    def test_nothing_leaves_the_system(self, tmp_path, attack_files):
        result = run(good_run(), tmp_path, attack_files["HID-001"])
        assert Outbox(result.outbox_path).rows() == []
        assert ATS(result.ats_path).get("C001").status == "new"

    def test_the_review_names_the_rule_that_caused_it(self, tmp_path, attack_files):
        recorded = events(run(good_run(), tmp_path, attack_files["HID-001"]))
        review = [e for e in recorded if e["event"] == "review_requested"]
        assert review and review[0]["cause_rule_id"] == "POL-002"

    def test_a_clean_document_goes_all_the_way_through(self, tmp_path, attack_files):
        result = run(good_run(), tmp_path, attack_files["DIR-001"], preset="isolation_only")
        assert result.status == "done"
        assert len(Outbox(result.outbox_path).rows()) == 1


class TestReviewCauseAttribution:
    def test_a_reader_failure_does_not_borrow_a_policy_rule_id(self, tmp_path,
                                                               attack_files):
        """Otherwise the report credits the policy layer for a mechanical failure."""
        client = FakeClient(text("no"), text("still no"))
        result = run(client, tmp_path, attack_files["DIR-001"])
        assert result.status == "review"
        review = [e for e in events(result) if e["event"] == "review_requested"]
        assert review[0].get("cause_rule_id") is None
        assert review[0]["reason"] == "reader_failed"

    def test_reader_failure_is_logged(self, tmp_path, attack_files):
        result = run(FakeClient(text("no"), text("no")), tmp_path, attack_files["DIR-001"])
        names = [e["event"] for e in events(result)]
        assert names.count("reader_validation_failed") == 2


class TestHardenedToolEffects:
    def test_the_recipient_comes_from_the_ats_not_the_model(self, tmp_path,
                                                            attack_files):
        """The attacker asks for a redirect; the tool has no `to` to redirect."""
        result = run(CompliantClient(), tmp_path, attack_files["DIR-003"],
                     preset="isolation_only")
        (row,) = Outbox(result.outbox_path).rows()
        assert row["to"] == "jordan.avery@example.com"

    def test_the_ats_note_comes_from_a_template_not_the_model(self, tmp_path,
                                                              attack_files):
        result = run(CompliantClient(), tmp_path, attack_files["DIR-001"],
                     preset="isolation_only")
        assert "DOORMAN-PWN" not in ATS(result.ats_path).get("C001").notes

    def test_a_persuaded_model_can_still_inflate_the_score(self, tmp_path,
                                                          attack_files):
        """Isolation does not stop this. The classifier and taint gate do, which
        is exactly the ablation the report is meant to show."""
        result = run(CompliantClient(), tmp_path, attack_files["DIR-001"],
                     preset="isolation_only")
        assert result.score == 97


class TestBudgetsAcrossPhases:
    def test_a_second_email_is_denied(self, tmp_path, attack_files):
        client = FakeClient(
            tool_use(("emit_profile", DEFAULT_PROFILE)),
            tool_use(("score_candidate", {"score": 34, "rationale": "x"})),
            tool_use(("propose_decision", {"status": "reject", "rationale": "x"})),
            tool_use(("send_email", {"template_id": "reject_polite"})),
            tool_use(("send_email", {"template_id": "advance_next_steps"})),
            tool_use(("ats_update", {"status": "reject"})),
        )
        result = run(client, tmp_path, attack_files["DIR-001"], preset="isolation_only")
        assert len(Outbox(result.outbox_path).rows()) == 1
