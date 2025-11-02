"""CLI surface (spec 23). Every command exists; none pretends to work yet."""

from __future__ import annotations

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


def test_stubs_raise_and_name_their_phase(tmp_path):
    doc = tmp_path / "cv.pdf"
    doc.write_bytes(b"%PDF-1.4\n")
    result = runner.invoke(app, ["ingest", str(doc)])
    assert isinstance(result.exception, NotImplementedError)
    assert "Phase 1" in str(result.exception)
