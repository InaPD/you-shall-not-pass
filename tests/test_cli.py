"""CLI surface (spec 23)."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from doorman.cli import app

runner = CliRunner()

TOP_LEVEL = ("ingest", "run", "redteam", "benign", "approve", "report")


def test_help_lists_every_command():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in TOP_LEVEL:
        assert command in result.stdout


@pytest.mark.parametrize("group,sub", [("redteam", "build"), ("redteam", "run"),
                                       ("benign", "build"), ("benign", "run")])
def test_subcommands_exist(group, sub):
    result = runner.invoke(app, [group, "--help"])
    assert result.exit_code == 0
    assert sub in result.stdout


def test_configs_command_lists_presets():
    result = runner.invoke(app, ["configs"])
    assert result.exit_code == 0
    assert "full_minus_classifier" in result.stdout
    assert "(no defences)" in result.stdout  # the `none` baseline


def test_unknown_config_is_rejected_before_any_work(tmp_path):
    doc = tmp_path / "cv.pdf"
    doc.write_bytes(b"%PDF-1.4\n")
    result = runner.invoke(
        app, ["run", "--config", "mostly", "--doc", str(doc), "--candidate", "C1", "--job", "J1"]
    )
    assert result.exit_code != 0
    assert "unknown config" in result.output


def test_unknown_approval_mode_is_rejected(tmp_path):
    doc = tmp_path / "cv.pdf"
    doc.write_bytes(b"%PDF-1.4\n")
    result = runner.invoke(
        app,
        ["run", "--config", "full", "--doc", str(doc), "--candidate", "C1", "--job", "J1",
         "--approval", "maybe"],
    )
    assert result.exit_code != 0


@pytest.mark.parametrize(
    "argv,phase",
    [
        (["benign", "build"], "Phase 4"),
        (["benign", "run", "--configs", "full"], "Phase 4"),
    ],
)
def test_unimplemented_commands_raise_and_name_their_phase(argv, phase):
    result = runner.invoke(app, argv)
    assert isinstance(result.exception, NotImplementedError)
    assert phase in str(result.exception)


def test_ingest_reports_rules_on_a_real_attack_file():
    from corpus.attacks import build

    path = build.build_one(
        next(s for s in build.load_manifest() if s.id == "HID-001")
    )
    result = runner.invoke(app, ["ingest", str(path)])
    assert result.exit_code == 0, result.output
    assert "ING-001" in result.output


def test_approve_rejects_an_unknown_run():
    result = runner.invoke(app, ["approve", "--run", "does-not-exist"])
    assert result.exit_code != 0
    assert "no run at" in result.output


def test_redteam_run_is_never_invoked_without_a_fake_client():
    """A guard, not a behaviour test: `doorman redteam run` builds a real client
    and executes the whole matrix, writing into harness/out/ and runs/. No test
    may call it - drive harness.run_matrix.run(client_factory=...) instead."""
    # Built at runtime so this guard does not match its own source. Matches the
    # actual invocation, not the --help parametrize that merely names the pair.
    needle = "invoke(app, [" + '"redteam", ' + '"run"'
    offenders = [
        path.name
        for path in Path(__file__).parent.glob("test_*.py")
        if needle in path.read_text(encoding="utf-8")
    ]
    assert not offenders, f"these tests invoke the real matrix: {offenders}"


def test_redteam_build_renders_the_manifest():
    result = runner.invoke(app, ["redteam", "build"])
    assert result.exit_code == 0, result.output
    assert "attack(s) built" in result.output
