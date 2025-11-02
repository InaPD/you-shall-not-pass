"""Doorman CLI (spec 23).

Phase 0 wires up the full command surface so the shape of the tool is fixed early;
each command raises until its phase lands. The phase is named in the error so an
unimplemented path is never mistaken for a bug.
"""

from __future__ import annotations

from pathlib import Path

import typer

from doorman import config

app = typer.Typer(
    name="doorman",
    help="Recruiting agent with a layered prompt-injection defence and a red-team harness.",
    no_args_is_help=True,
    add_completion=False,
)
redteam_app = typer.Typer(help="Attack corpus: build and run.", no_args_is_help=True)
benign_app = typer.Typer(help="Benign corpus: build and run.", no_args_is_help=True)
app.add_typer(redteam_app, name="redteam")
app.add_typer(benign_app, name="benign")

_APPROVAL_MODES = ("auto", "deny", "human")


def _todo(what: str, phase: str) -> None:
    raise NotImplementedError(f"{what} lands in {phase}; see PLAN.md")


def _validate_config_name(name: str) -> str:
    if name not in config.PRESETS:
        raise typer.BadParameter(
            f"unknown config {name!r}; choose one of {', '.join(config.PRESET_NAMES)}"
        )
    return name


def _validate_configs(value: str) -> str:
    for name in (n.strip() for n in value.split(",") if n.strip()):
        _validate_config_name(name)
    return value


def _validate_approval(value: str) -> str:
    if value not in _APPROVAL_MODES:
        raise typer.BadParameter(f"choose one of {', '.join(_APPROVAL_MODES)}")
    return value


@app.command()
def ingest(
    file: Path = typer.Argument(..., exists=True, dir_okay=False, help="PDF or DOCX to parse."),
) -> None:
    """Print a Document summary plus any ING-* flags."""
    _todo("ingest", "Phase 1")


@app.command()
def run(
    config_name: str = typer.Option(
        ..., "--config", callback=lambda v: _validate_config_name(v), help="Defence preset."
    ),
    doc: Path = typer.Option(..., "--doc", exists=True, dir_okay=False, help="Resume to screen."),
    candidate: str = typer.Option(..., "--candidate", help="Candidate id in the ATS seed."),
    job: str = typer.Option(..., "--job", help="Job spec id."),
    approval: str = typer.Option(
        "human", "--approval", callback=lambda v: _validate_approval(v),
        help="How APR-* actions resolve: auto | deny | human.",
    ),
) -> None:
    """Screen one candidate end to end under a defence preset."""
    _todo("run", "Phase 1 (single-call flow) and Phase 2 (phased flow)")


@redteam_app.command("build")
def redteam_build() -> None:
    """Render the attack manifest to corpus/attacks/out/."""
    _todo("redteam build", "Phase 1")


@redteam_app.command("run")
def redteam_run(
    configs: str = typer.Option(
        ..., "--configs", callback=lambda v: _validate_configs(v), help="Comma-separated presets."
    ),
    repeats: int = typer.Option(1, "--repeats", min=1, help="Repeats per (config, item)."),
    approval: str = typer.Option(
        "auto", "--approval", callback=lambda v: _validate_approval(v), help="auto | deny."
    ),
    only: str = typer.Option("", "--only", help="Attack ids or a family name to restrict to."),
) -> None:
    """Run the attack matrix."""
    _todo("redteam run", "Phase 2")


@benign_app.command("build")
def benign_build() -> None:
    """Generate and render the 100 benign resumes."""
    _todo("benign build", "Phase 4")


@benign_app.command("run")
def benign_run(
    configs: str = typer.Option(
        ..., "--configs", callback=lambda v: _validate_configs(v), help="Comma-separated presets."
    ),
) -> None:
    """Run the benign matrix for false-positive metrics."""
    _todo("benign run", "Phase 4")


@app.command()
def approve(
    run_id: str = typer.Option(..., "--run", help="Run id whose pending actions to review."),
) -> None:
    """Review and resolve pending irreversible actions."""
    _todo("approve", "Phase 3")


@app.command()
def report() -> None:
    """Turn results.jsonl into REPORT.md and summary.json."""
    _todo("report", "Phase 2 (minimal) and Phase 4 (full)")


@app.command()
def configs() -> None:
    """List the defence presets and which layers each enables."""
    for name, cfg in config.PRESETS.items():
        layers = [k for k, v in cfg.as_dict().items() if k != "name" and v]
        typer.echo(f"{name:<22} {', '.join(layers) if layers else '(no defences)'}")


if __name__ == "__main__":  # pragma: no cover
    app()
