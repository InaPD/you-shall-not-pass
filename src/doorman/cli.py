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
    from doorman.ingest import hidden, loader

    settings = config.load_settings()
    doc = loader.load(file, settings)
    typer.echo(f"{doc.doc_id}  kind={doc.kind}  pages={doc.page_count}  sha256={doc.sha256[:16]}")
    typer.echo(f"spans={len(doc.spans)}  hidden={len(doc.hidden_spans())}  "
               f"metadata_keys={len(doc.metadata)}")
    fired = hidden.fired_rules(doc)
    typer.echo(f"rules fired: {', '.join(fired) if fired else '(none)'}")
    for span in doc.hidden_spans():
        preview = span.text.strip()[:60].replace("\n", " ")
        typer.echo(f"  {span.id:<16} {','.join(span.hidden_reasons):<12} {preview!r}")
    for key, reasons in doc.metadata_flags.items():
        typer.echo(f"  {key:<28} {','.join(reasons)}")


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
    import anthropic

    from doorman.agent import orchestrator

    settings = config.load_settings()
    cfg = config.preset(config_name)
    client = anthropic.Anthropic()
    result = orchestrator.run_candidate(
        client, settings, cfg, doc_path=doc, candidate_id=candidate, job_id=job
    )
    typer.echo(
        f"run {result.run_id}  status={result.status}  score={result.score}  "
        f"decision={result.decision}  taint={result.taint}"
    )
    typer.echo(f"  rules fired : {', '.join(result.rules_fired) or '(none)'}")
    typer.echo(f"  events      : {result.events_path}")
    typer.echo(f"  outbox      : {result.outbox_path}")
    typer.echo(f"  tokens      : in={result.input_tokens} out={result.output_tokens}")


@redteam_app.command("build")
def redteam_build() -> None:
    """Render the attack manifest to corpus/attacks/out/."""
    from corpus.attacks import build

    built = build.build_all()
    for spec, path in built:
        typer.echo(f"{spec.id:<9} {spec.family:<12} {spec.placement:<15} {path}")
    typer.echo(f"{len(built)} attack(s) built")


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
    from harness import run_matrix

    names = [n.strip() for n in configs.split(",") if n.strip()]
    only_ids = [n.strip() for n in only.split(",") if n.strip()] or None
    path = run_matrix.run(
        configs=names, repeats=repeats, only=only_ids, approval=approval
    )
    typer.echo(f"results appended to {path}")


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
    from harness import report as report_builder

    path = report_builder.build()
    typer.echo(f"wrote {path}")
    typer.echo(f"wrote {report_builder.SUMMARY_PATH}")


@app.command()
def configs() -> None:
    """List the defence presets and which layers each enables."""
    for name, cfg in config.PRESETS.items():
        layers = [k for k, v in cfg.as_dict().items() if k != "name" and v]
        typer.echo(f"{name:<22} {', '.join(layers) if layers else '(no defences)'}")


if __name__ == "__main__":  # pragma: no cover
    app()
