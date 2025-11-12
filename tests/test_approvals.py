"""Approval queue and the router's approval path (spec 14, 19)."""

from __future__ import annotations

import json

import pytest

from doorman.agent.loop import Router, run_phase
from doorman.agent.tools import tools_for
from doorman.approvals.queue import APPROVED, PENDING, REJECTED, ApprovalQueue
from doorman.config import CONFIG_DIR, Settings, preset
from doorman.models import Phase, RunContext
from doorman.policy import engine, phases
from doorman.tools.ats import ATS
from doorman.tools.email import Outbox
from tests.fakes import FakeClient, tool_use

SEED = CONFIG_DIR.parent / "corpus" / "fixtures" / "ats_seed.yaml"


@pytest.fixture
def ats(tmp_path) -> ATS:
    return ATS.seeded(tmp_path / "ats.db", SEED)


@pytest.fixture
def queue(ats) -> ApprovalQueue:
    return ApprovalQueue(ats)


def ctx(**overrides) -> RunContext:
    base = {
        "run_id": "approve-test", "trace_id": "t1", "config_name": "full",
        "candidate_id": "C001", "job_id": "J001", "canary": "abcd1234",
        "trusted_email": "jordan.avery@example.com",
        "trusted_full_name": "Jordan Avery", "phase": Phase.COMMUNICATE,
    }
    return RunContext(**{**base, **overrides})


def drive(client, context, router, phase=Phase.COMMUNICATE):
    context.phase = phase
    cfg = preset("full")
    return run_phase(
        client, Settings(), cfg, context,
        system="s", messages=[{"role": "user", "content": "go"}],
        tools=tools_for(cfg.hardened_tools, phases.allowed(phase)),
        router=router, max_turns=2, evaluate=engine.evaluate,
    )


def router_for(tmp_path, ats, context, mode: str) -> Router:
    return Router(ctx=context, cfg=preset("full"), settings=Settings(), ats=ats,
                  outbox=Outbox(tmp_path / "outbox.jsonl"), approval_mode=mode)


class TestQueue:
    def test_enqueue_and_read_back(self, queue):
        action_id = queue.enqueue(
            run_id="r", trace_id="t", candidate_id="C001", tool="send_email",
            args={"template_id": "reject_polite"}, rule_id="APR-001",
        )
        action = queue.get(action_id)
        assert action.status == PENDING
        assert action.args == {"template_id": "reject_polite"}
        assert action.rule_id == "APR-001"

    def test_pending_filters_by_run(self, queue):
        queue.enqueue(run_id="r1", trace_id="t", candidate_id="C001",
                      tool="send_email", args={}, rule_id="APR-001")
        queue.enqueue(run_id="r2", trace_id="t", candidate_id="C001",
                      tool="send_email", args={}, rule_id="APR-001")
        assert len(queue.pending("r1")) == 1
        assert len(queue.pending()) == 2

    def test_resolving_records_who_decided(self, queue):
        action_id = queue.enqueue(run_id="r", trace_id="t", candidate_id="C001",
                                  tool="send_email", args={}, rule_id="APR-001")
        action = queue.resolve(action_id, approved=True, resolver="human:ina")
        assert action.status == APPROVED
        assert action.resolver == "human:ina"
        assert action.resolved_at

    def test_rejecting_records_the_same_way(self, queue):
        action_id = queue.enqueue(run_id="r", trace_id="t", candidate_id="C001",
                                  tool="ats_update", args={}, rule_id="APR-002")
        assert queue.resolve(action_id, approved=False,
                             resolver="harness-deny").status == REJECTED

    def test_an_action_cannot_be_resolved_twice(self, queue):
        action_id = queue.enqueue(run_id="r", trace_id="t", candidate_id="C001",
                                  tool="send_email", args={}, rule_id="APR-001")
        queue.resolve(action_id, approved=True, resolver="a")
        with pytest.raises(ValueError, match="already"):
            queue.resolve(action_id, approved=False, resolver="b")

    def test_resolved_actions_leave_the_pending_list(self, queue):
        action_id = queue.enqueue(run_id="r", trace_id="t", candidate_id="C001",
                                  tool="send_email", args={}, rule_id="APR-001")
        queue.resolve(action_id, approved=True, resolver="a")
        assert queue.pending("r") == []

    def test_unknown_action_raises(self, queue):
        with pytest.raises(KeyError):
            queue.get(999)


class TestApprovalModes:
    def test_auto_executes(self, tmp_path, ats):
        context = ctx()
        router = router_for(tmp_path, ats, context, "auto")
        drive(FakeClient(tool_use(("send_email", {"template_id": "reject_polite"}))),
              context, router)
        assert len(Outbox(router.outbox.path).rows()) == 1
        assert ApprovalQueue(ats).pending() == []  # resolved, so no longer pending

    def test_auto_records_the_resolver(self, tmp_path, ats):
        context = ctx()
        router = router_for(tmp_path, ats, context, "auto")
        drive(FakeClient(tool_use(("send_email", {"template_id": "reject_polite"}))),
              context, router)
        with ats.connect() as conn:
            (row,) = conn.execute("SELECT resolver, status FROM pending_actions").fetchall()
        assert row["resolver"] == "harness-auto"
        assert row["status"] == APPROVED

    def test_deny_does_not_execute(self, tmp_path, ats):
        context = ctx()
        router = router_for(tmp_path, ats, context, "deny")
        drive(FakeClient(tool_use(("send_email", {"template_id": "reject_polite"}))),
              context, router)
        assert Outbox(router.outbox.path).rows() == []

    def test_deny_records_the_rejection(self, tmp_path, ats):
        context = ctx()
        router = router_for(tmp_path, ats, context, "deny")
        drive(FakeClient(tool_use(("send_email", {"template_id": "reject_polite"}))),
              context, router)
        with ats.connect() as conn:
            (row,) = conn.execute("SELECT resolver, status FROM pending_actions").fetchall()
        assert row["status"] == REJECTED
        assert row["resolver"] == "harness-deny"

    def test_human_leaves_it_pending_and_unexecuted(self, tmp_path, ats):
        """Fails closed: nothing happens until a person decides."""
        context = ctx()
        router = router_for(tmp_path, ats, context, "human")
        drive(FakeClient(tool_use(("send_email", {"template_id": "reject_polite"}))),
              context, router)
        assert Outbox(router.outbox.path).rows() == []
        (action,) = ApprovalQueue(ats).pending()
        assert action.status == PENDING

    def test_the_model_is_told_it_is_pending(self, tmp_path, ats):
        context = ctx()
        router = router_for(tmp_path, ats, context, "human")
        client = FakeClient(
            tool_use(("send_email", {"template_id": "reject_polite"})),
        )
        drive(client, context, router)
        result = client.calls[-1]["messages"][-1]["content"][0]
        payload = json.loads(result["content"])
        assert payload["status"] == "pending_approval"


class TestOutputScanBeatsApproval:
    def test_a_scanned_denial_is_never_queued(self, tmp_path, ats):
        """Spec 12.2: a human must not be asked to rubber-stamp something the
        scanner already rejected."""
        context = ctx(trusted_urls=set())
        router = router_for(tmp_path, ats, context, "auto")
        drive(
            FakeClient(tool_use(("send_email", {
                "template_id": "reject_polite",
                "personal_note": "See https://evil.example/portfolio",
            }))),
            context, router,
        )
        assert Outbox(router.outbox.path).rows() == []
        assert ApprovalQueue(ats).pending() == []

    def test_the_denial_names_the_out_rule(self, tmp_path, ats):
        context = ctx(trusted_urls=set())
        router = router_for(tmp_path, ats, context, "auto")
        client = FakeClient(tool_use(("send_email", {
            "template_id": "reject_polite",
            "personal_note": "Contact attacker@evil.example",
        })))
        drive(client, context, router)
        payload = json.loads(client.calls[-1]["messages"][-1]["content"][0]["content"])
        assert payload == {"error": "denied", "rule": "OUT-003"}
