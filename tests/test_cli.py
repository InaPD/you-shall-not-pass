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


def test_every_command_is_implemented():
    """Phase 0 shipped the whole command surface as stubs. Nothing may still be
    one: an unimplemented command is a hole in the CLI, not a placeholder."""
    source = Path(__file__).parents[1] / "src" / "doorman" / "cli.py"
    assert "NotImplementedError" not in source.read_text(encoding="utf-8")


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


@pytest.mark.parametrize("group", ["redteam", "benign"])
def test_the_matrix_commands_are_never_invoked_from_a_test(group):
    """A guard, not a behaviour test.

    `doorman redteam run` and `doorman benign run` build a real client and
    execute the whole matrix, writing into harness/out/results.jsonl and runs/.
    A test that calls one pollutes the results file a report is built from, which
    is how a fabricated number gets into REPORT.md. Drive
    `harness.run_matrix.run(client_factory=...)` with an explicit results_path
    instead. The same goes for `benign build`, which spends money on generation.
    """
    # Built at runtime so this guard does not match its own source. Matches the
    # actual invocation, not the --help parametrize that merely names the pair.
    subcommands = ["run", "build"] if group == "benign" else ["run"]
    needles = ["invoke(app, [" + f'"{group}", ' + f'"{sub}"' for sub in subcommands]
    offenders = sorted({
        path.name
        for path in Path(__file__).parent.glob("test_*.py")
        for needle in needles
        if needle in path.read_text(encoding="utf-8")
    })
    assert not offenders, f"these tests invoke the real matrix: {offenders}"


def test_redteam_build_renders_the_manifest():
    result = runner.invoke(app, ["redteam", "build"])
    assert result.exit_code == 0, result.output
    assert "attack(s) built" in result.output
