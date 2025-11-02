"""ActionLog behaviour and the two invariants it enforces (spec 15, 21.4, 21.10)."""

from __future__ import annotations

import json

import pytest

from doorman import trace
from doorman.models import Phase, RunContext, Taint


@pytest.fixture
def ctx() -> RunContext:
    return RunContext(
        run_id="run-test",
        trace_id="trace-1",
        config_name="full",
        candidate_id="C001",
        job_id="J001",
        phase=Phase.SCORE,
        canary="deadbeefdeadbeef",
        trusted_email="jane@example.com",
        trusted_full_name="Jane Doe",
    )


@pytest.fixture
def events(tmp_path, ctx):
    """Capture this run's events and yield a reader for them."""
    trace.open_run(ctx.run_id, tmp_path)
    yield lambda: [
        json.loads(line)
        for line in (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    trace.close_run(ctx.run_id)


class TestCommonFields:
    def test_every_event_carries_the_common_fields(self, ctx, events):
        trace.review_requested(ctx, cause_rule_id="POL-002")
        (event,) = events()
        for key in ("ts", "run_id", "trace_id", "config", "candidate_id", "phase", "event"):
            assert key in event, key
        assert event["event"] == "review_requested"
        assert event["phase"] == "score"
        assert event["config"] == "full"


class TestRuleIdValidation:
    def test_unknown_rule_id_raises(self, ctx, events):
        """Spec 21.4: an unregistered rule id is a programming error."""
        with pytest.raises(KeyError, match="unknown rule_id"):
            trace.review_requested(ctx, cause_rule_id="POL-999")

    def test_unknown_rule_id_in_a_list_also_raises(self, ctx, events):
        """The processor catches ids the call site never names individually."""
        with pytest.raises(KeyError, match="unknown rule_id"):
            trace._emit(ctx, "run_finished", rules_fired=["ING-001", "XXX-001"])

    def test_known_rule_ids_pass(self, ctx, events):
        trace._emit(ctx, "run_finished", rules_fired=["ING-001", "CLS-002", "POL-002"])
        assert events()[0]["rules_fired"] == ["ING-001", "CLS-002", "POL-002"]


class TestDebugRouting:
    def test_policy_passes_reach_the_file(self, ctx, events):
        """Spec 11.3: allows are logged at debug, so they are in the file..."""
        trace.policy_decision(ctx, tool="score_candidate", decision="allow")
        (event,) = events()
        assert event["decision"] == "allow"
        assert event["level"] == "debug"

    def test_denials_are_info(self, ctx, events):
        trace.policy_decision(
            ctx, tool="send_email", decision="deny", rule_id="POL-002", reason="tainted"
        )
        (event,) = events()
        assert event["level"] == "info"
        assert event["rule_id"] == "POL-002"


class TestRedaction:
    def test_redact_replaces_strings_with_lengths(self):
        assert trace.redact("hello") == "<5 chars>"

    def test_redact_preserves_structure(self):
        out = trace.redact({"score": 90, "rationale": "abc", "tags": ["xy"]})
        assert out == {"score": 90, "rationale": "<3 chars>", "tags": ["<2 chars>"]}

    def test_tool_call_proposed_logs_no_free_text(self, ctx, events):
        """Spec 21.10: the argument value must not appear in the log."""
        args = {"score": 95, "rationale": "secret rationale text"}
        trace.tool_call_proposed(
            ctx,
            tool="score_candidate",
            args_sha256=trace.sha256_text(json.dumps(args)),
            args_redacted=trace.redact(args),
        )
        (event,) = events()
        assert "secret rationale text" not in json.dumps(event)
        assert event["args_redacted"]["score"] == 95
        assert len(event["args_sha256"]) == 64


class TestPerRunRouting:
    def test_events_for_another_run_do_not_land_in_this_file(self, ctx, events, tmp_path):
        """The harness runs up to 4 candidates concurrently; logs must not cross."""
        other = ctx.model_copy(update={"run_id": "run-other"})
        trace.review_requested(other, cause_rule_id="POL-002")
        trace.review_requested(ctx, cause_rule_id="POL-002")
        written = events()
        assert len(written) == 1
        assert written[0]["run_id"] == "run-test"


class TestEventShapes:
    def test_taint_changed_uses_from_and_to(self, ctx, events):
        trace.taint_changed(
            ctx, from_taint=Taint.CLEAN, to_taint=Taint.SUSPICIOUS, cause_rule_id="ING-001"
        )
        (event,) = events()
        assert event["from"] == "clean"
        assert event["to"] == "suspicious"
        assert event["cause_rule_id"] == "ING-001"

    def test_none_valued_fields_are_omitted(self, ctx, events):
        trace.run_finished(
            ctx, status="ok", duration_s=1.0, total_input_tokens=10, total_output_tokens=2
        )
        (event,) = events()
        assert "score" not in event
        assert "decision" not in event

    def test_sha256_helpers_are_stable(self):
        assert trace.sha256_text("abc") == trace.sha256_bytes(b"abc")
        assert len(trace.sha256_text("abc")) == 64
