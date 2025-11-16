"""Doorman CLI (spec 23).

The full command surface was wired up in Phase 0 and each command was filled in
by the phase that owned it. Every one of them is now implemented.
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

# Spec 18 caps concurrency at 4; the matrix runner enforces it, this is just the
# default the CLI asks for.
DEFAULT_CONCURRENCY = 4


def _split(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


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
        client, settings, cfg, doc_path=doc, candidate_id=candidate, job_id=job,
        approval=approval,
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
    concurrency: int = typer.Option(
        DEFAULT_CONCURRENCY, "--concurrency", min=1, help="Runs in flight, capped at 4."
    ),
) -> None:
    """Run the attack matrix."""
    from harness import run_matrix

    path = run_matrix.run(
        configs=_split(configs), corpus="attacks", repeats=repeats,
        only=_split(only) or None, approval=approval, concurrency=concurrency,
    )
    typer.echo(f"results appended to {path}")


@benign_app.command("build")
def benign_build(
    only: str = typer.Option("", "--only", help="Benign ids to restrict to."),
) -> None:
    """Generate and render the 100 benign resumes.

    Cached: a profile already in `corpus/benign/out/` is reused, so rerunning
    this costs nothing and, more to the point, does not change the corpus a
    report was measured against.
    """
    import anthropic
    from corpus.benign import generate

    settings = config.load_settings()
    specs = generate.load_specs()
    wanted = set(_split(only))
    if wanted:
        specs = [s for s in specs if s.id in wanted]
    client = anthropic.Anthropic()
    cached = sum(1 for spec in specs if generate.profile_path(spec).is_file())
    typer.echo(f"{len(specs)} spec(s), {cached} already generated")
    for spec, path in generate.build_all(client, model=settings.reader_model, specs=specs):
        mark = "hard" if spec.is_hard_negative else "    "
        typer.echo(f"{spec.id:<9} {mark} {spec.layout:<14} {path}")


@benign_app.command("run")
def benign_run(
    configs: str = typer.Option(
        ..., "--configs", callback=lambda v: _validate_configs(v), help="Comma-separated presets."
    ),
    repeats: int = typer.Option(1, "--repeats", min=1, help="Repeats per (config, item)."),
    only: str = typer.Option("", "--only", help="Benign ids, `benign` or `hard_negative`."),
    concurrency: int = typer.Option(
        DEFAULT_CONCURRENCY, "--concurrency", min=1, help="Runs in flight, capped at 4."
    ),
) -> None:
    """Run the benign matrix for false-positive metrics.

    Always `--approval auto`: a held approval is the design working, so denying
    them would turn every irreversible action into a false positive.
    """
    from harness import run_matrix

    path = run_matrix.run(
        configs=_split(configs), corpus="benign", repeats=repeats,
        only=_split(only) or None, approval="auto", concurrency=concurrency,
    )
    typer.echo(f"results appended to {path}")


@app.command()
def approve(
    run_id: str = typer.Option(..., "--run", help="Run id whose pending actions to review."),
) -> None:
    """Review and resolve pending irreversible actions."""

    from doorman.approvals.queue import ApprovalQueue
    from doorman.tools import effects
    from doorman.tools.ats import ATS
    from doorman.tools.email import Outbox

    directory = config.run_dir(run_id)
    if not directory.is_dir():
        raise typer.BadParameter(f"no run at {directory}")

    ats = ATS(directory / "ats.db")
    outbox = Outbox(directory / "outbox.jsonl")
    queue = ApprovalQueue(ats)
    actions = queue.pending(run_id)
    if not actions:
        typer.echo(f"no pending actions for {run_id}")
        return

    events = _load_events(directory / "events.jsonl")
    for action in actions:
        record = ats.get(action.candidate_id)
        typer.echo("")
        typer.echo(f"action {action.id}: {action.tool}  (held by {action.rule_id})")
        for line in effects.preview(action.tool, action.args, record):
            typer.echo(line)
        context = _context_lines(events, action.trace_id)
        if context:
            typer.echo("  why it was held:")
            for line in context:
                typer.echo(f"    {line}")
        choice = typer.prompt("  [a]pprove / [r]eject / [s]kip", default="s").strip().lower()
        if choice.startswith("s"):
            continue
        approved = choice.startswith("a")
        queue.resolve(action.id, approved=approved, resolver=f"human:{run_id}")
        if not approved:
            typer.echo("  rejected")
            continue
        if action.tool == "send_email":
            effects.send_email(outbox, run_id=run_id, record=record, args=action.args)
        elif action.tool == "ats_update":
            effects.ats_update(ats, candidate_id=action.candidate_id, args=action.args)
        typer.echo("  approved and executed")


def _load_events(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    import json

    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# Spec 14: show the human why this action was held, not just what it would do.
_CONTEXT_EVENTS = (
    "policy_decision", "hidden_text_detected", "classifier_verdict",
    "output_blocked", "taint_changed",
)


def _context_lines(events: list[dict], trace_id: str) -> list[str]:
    lines: list[str] = []
    for event in events:
        if event.get("trace_id") != trace_id:
            continue
        if event.get("event") not in _CONTEXT_EVENTS:
            continue
        if event.get("event") == "policy_decision" and event.get("decision") == "allow":
            continue
        detail = event.get("rule_id") or event.get("cause_rule_id") or ""
        locator = event.get("locator") or event.get("span_id") or event.get("metadata_key") or ""
        lines.append(f"{event['event']:<22} {detail:<9} {locator}".rstrip())
    return lines[:20]


@app.command()
def report() -> None:
    """Turn results.jsonl into REPORT.md and summary.json."""
    from harness import report as report_builder

    path = report_builder.build(readme_path=report_builder.README_PATH)
    typer.echo(f"wrote {path}")
    typer.echo(f"wrote {report_builder.SUMMARY_PATH}")
    typer.echo(f"updated the results section of {report_builder.README_PATH}")


@app.command()
def configs() -> None:
    """List the defence presets and which layers each enables."""
    for name, cfg in config.PRESETS.items():
        layers = [k for k, v in cfg.as_dict().items() if k != "name" and v]
        typer.echo(f"{name:<22} {', '.join(layers) if layers else '(no defences)'}")


if __name__ == "__main__":  # pragma: no cover
    app()
