"""The tool-use loop driven by scripted responses (spec 19).

Asserts the event sequence and, most importantly, that a denied tool is never
executed - the property the whole defence rests on.
"""

from __future__ import annotations

import json

import pytest

from doorman.agent.loop import Router, run_phase
from doorman.agent.tools import tools_for
from doorman.config import CONFIG_DIR, Settings, preset
from doorman.models import Phase, RunContext, Taint
from doorman.policy import engine, phases
from doorman.tools.ats import ATS
from doorman.tools.email import Outbox
from tests.fakes import FakeClient, text, tool_use

SEED = CONFIG_DIR.parent / "corpus" / "fixtures" / "ats_seed.yaml"


@pytest.fixture
def ctx() -> RunContext:
    return RunContext(
        run_id="loop-test", trace_id="t1", config_name="full",
        candidate_id="C001", job_id="J001", canary="abcd1234",
        trusted_email="jordan.avery@example.com", trusted_full_name="Jordan Avery",
        trusted_portfolio_url="https://portfolio.example/jordan-avery",
        phase=Phase.SCORE,
    )


@pytest.fixture
def router(tmp_path, ctx) -> Router:
    return Router(
        ctx=ctx, cfg=preset("full"), settings=Settings(),
        ats=ATS.seeded(tmp_path / "ats.db", SEED),
        outbox=Outbox(tmp_path / "outbox.jsonl"),
    )


def drive(client, ctx, router, *, phase=Phase.SCORE, cfg=None, with_policy=True,
          max_turns=4):
    cfg = cfg or preset("full")
    ctx.phase = phase
    return run_phase(
        client, Settings(), cfg, ctx,
        system="system", messages=[{"role": "user", "content": "go"}],
        tools=tools_for(cfg.hardened_tools, phases.allowed(phase)),
        router=router, max_turns=max_turns,
        evaluate=engine.evaluate if with_policy else None,
    )


class TestAllowPath:
    def test_an_allowed_call_executes(self, ctx, router):
        client = FakeClient(tool_use(("score_candidate", {"score": 41, "rationale": "x"})))
        drive(client, ctx, router)
        assert router.score == 41
        assert router.executed == ["score_candidate"]

    def test_the_tool_result_is_returned_to_the_model(self, ctx, router):
        client = FakeClient(
            tool_use(("score_candidate", {"score": 41, "rationale": "x"})), text()
        )
        drive(client, ctx, router)
        follow_up = client.calls[1]["messages"][-1]["content"][0]
        assert follow_up["type"] == "tool_result"
        assert json.loads(follow_up["content"])["score"] == 41


class TestDenyPath:
    def test_a_denied_tool_is_not_executed(self, ctx, router):
        """The central property: a denial means the mock is never reached."""
        client = FakeClient(tool_use(("send_email", {"template_id": "reject_polite"})))
        drive(client, ctx, router, phase=Phase.SCORE)  # wrong phase for send_email
        assert router.executed == []
        assert Outbox(router.outbox.path).rows() == []

    def test_the_model_is_told_which_rule_denied_it(self, ctx, router):
        client = FakeClient(
            tool_use(("send_email", {"template_id": "reject_polite"})), text()
        )
        drive(client, ctx, router, phase=Phase.SCORE)
        result = client.calls[1]["messages"][-1]["content"][0]
        assert json.loads(result["content"]) == {"error": "denied", "rule": "POL-001"}

    def test_a_retry_after_denial_is_evaluated_again(self, ctx, router):
        """Spec 12.2: every retry goes through the engine, no grandfathering."""
        client = FakeClient(
            tool_use(("score_candidate", {"score": 500, "rationale": "x"})),
            tool_use(("score_candidate", {"score": 101, "rationale": "x"})),
            tool_use(("score_candidate", {"score": 41, "rationale": "x"})),
        )
        drive(client, ctx, router)
        assert router.score == 41
        assert router.executed == ["score_candidate"]

    def test_tainted_email_never_reaches_the_outbox(self, ctx, router):
        ctx.taint = Taint.SUSPICIOUS
        client = FakeClient(tool_use(("send_email", {"template_id": "advance_next_steps"})))
        drive(client, ctx, router, phase=Phase.COMMUNICATE)
        assert Outbox(router.outbox.path).rows() == []

    def test_budget_stops_the_second_call(self, ctx, router):
        client = FakeClient(
            tool_use(("score_candidate", {"score": 41, "rationale": "a"})),
            tool_use(("score_candidate", {"score": 99, "rationale": "b"})),
        )
        drive(client, ctx, router)
        assert router.executed == ["score_candidate"]
        assert router.score == 41  # the second call was denied, not applied


class TestPolicyOff:
    def test_without_the_engine_everything_executes(self, ctx, router):
        """This is what `none` and `prompt_only` look like."""
        client = FakeClient(tool_use(("score_candidate", {"score": 9999, "rationale": "x"})))
        drive(client, ctx, router, with_policy=False)
        assert router.score == 9999


class TestTermination:
    def test_a_text_only_response_ends_the_phase(self, ctx, router):
        result = drive(FakeClient(text("No tool needed.")), ctx, router)
        assert result.status == "no_tool_call"

    def test_max_turns_is_respected(self, ctx, router):
        client = FakeClient(*[tool_use(("ats_lookup", {}))] * 10)
        result = drive(client, ctx, router, max_turns=3)
        assert result.status == "max_turns"
        assert len(client.calls) == 3

    def test_tokens_accumulate_across_turns(self, ctx, router):
        client = FakeClient(tool_use(("ats_lookup", {})), tool_use(("ats_lookup", {})))
        result = drive(client, ctx, router, max_turns=2)
        assert result.input_tokens == 2000
        assert result.output_tokens == 100


class TestParallelToolUse:
    def test_each_call_in_one_response_is_evaluated_separately(self, ctx, router):
        client = FakeClient(
            tool_use(
                ("score_candidate", {"score": 41, "rationale": "ok"}),
                ("send_email", {"template_id": "reject_polite"}),
            ),
            text(),
        )
        drive(client, ctx, router, phase=Phase.SCORE)
        assert router.executed == ["score_candidate"]  # the email was denied
        results = client.calls[1]["messages"][-1]["content"]
        assert len(results) == 2
        assert json.loads(results[1]["content"])["error"] == "denied"


class TestEnvelopes:
    def test_portfolio_text_is_enveloped(self, ctx, router):
        client = FakeClient(
            tool_use(("fetch_portfolio", {"url": "https://portfolio.example/jordan-avery"})),
            text(),
        )
        drive(client, ctx, router)
        payload = json.loads(client.calls[1]["messages"][-1]["content"][0]["content"])
        assert payload["text"].startswith('<untrusted_data source="portfolio_page"')

    def test_ats_notes_are_enveloped(self, ctx, router):
        client = FakeClient(tool_use(("ats_lookup", {})), text())
        drive(client, ctx, router)
        payload = json.loads(client.calls[1]["messages"][-1]["content"][0]["content"])
        assert payload["notes"].startswith('<untrusted_data source="ats_notes"')

    def test_trusted_ats_fields_are_not_enveloped(self, ctx, router):
        client = FakeClient(tool_use(("ats_lookup", {})), text())
        drive(client, ctx, router)
        payload = json.loads(client.calls[1]["messages"][-1]["content"][0]["content"])
        assert payload["full_name"] == "Jordan Avery"
        assert payload["email"] == "jordan.avery@example.com"
