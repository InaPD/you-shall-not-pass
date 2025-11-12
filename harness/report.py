"""results.jsonl -> REPORT.md and summary.json (spec 18)."""

from __future__ import annotations

import json
import subprocess
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from doorman.config import PRESET_NAMES, Settings

OUT_DIR = Path(__file__).resolve().parent / "out"
RESULTS_PATH = OUT_DIR / "results.jsonl"
SUMMARY_PATH = OUT_DIR / "summary.json"
REPORT_PATH = Path(__file__).resolve().parents[1] / "REPORT.md"

ALL_ROW = "all attacks"


def load_results(path: Path = RESULTS_PATH) -> list[dict[str, Any]]:
    if not Path(path).is_file():
        return []
    return [
        json.loads(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _git_sha() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def _pct(numerator: int, denominator: int) -> str:
    return "-" if not denominator else f"{100.0 * numerator / denominator:.0f}%"


def asr_table(rows: list[dict], configs: list[str]) -> tuple[list[str], dict]:
    """ASR by family x config. Cell is `executed% (reached%)` with n."""
    buckets: dict[tuple[str, str], list[dict]] = defaultdict(list)
    families: list[str] = []
    for row in rows:
        family = row.get("family", "?")
        if family not in families:
            families.append(family)
        buckets[(family, row["config"])].append(row)
        buckets[(ALL_ROW, row["config"])].append(row)

    lines = [
        "| family | " + " | ".join(configs) + " |",
        "|---" * (len(configs) + 1) + "|",
    ]
    summary: dict[str, dict[str, Any]] = {}
    for family in [*sorted(families), ALL_ROW]:
        cells = []
        summary[family] = {}
        for config in configs:
            group = buckets.get((family, config), [])
            n = len(group)
            executed = sum(1 for r in group if r.get("executed"))
            reached = sum(1 for r in group if r.get("reached"))
            cells.append(
                "-" if not n else f"{_pct(executed, n)} ({_pct(reached, n)}) n={n}"
            )
            summary[family][config] = {
                "n": n, "executed": executed, "reached": reached,
                "executed_pct": None if not n else round(100 * executed / n, 1),
                "reached_pct": None if not n else round(100 * reached / n, 1),
            }
        lines.append(f"| {family} | " + " | ".join(cells) + " |")
    return lines, summary


def rules_table(rows: list[dict], configs: list[str]) -> tuple[list[str], dict]:
    """Which layer is actually doing the work."""
    counts: dict[str, Counter] = {config: Counter() for config in configs}
    for row in rows:
        counts[row["config"]].update(row.get("rules_fired") or [])
    from doorman.policy import rules as rule_registry

    # Every rule, not just the ones that fired: a rule that never fires across
    # the whole corpus is itself a result worth showing.
    every_rule = sorted(rule_registry.RULES)
    if not rows:
        return ["_No runs recorded._"], {}
    lines = [
        "| rule | " + " | ".join(configs) + " |",
        "|---" * (len(configs) + 1) + "|",
    ]
    for rule in every_rule:
        lines.append(
            f"| {rule} | " + " | ".join(str(counts[c][rule]) for c in configs) + " |"
        )
    return lines, {c: dict(counts[c]) for c in configs}


def ablation_paragraph(summary: dict, configs: list[str]) -> str:
    overall = summary.get(ALL_ROW, {})

    def pct(config: str) -> float | None:
        return (overall.get(config) or {}).get("executed_pct")

    parts: list[str] = []
    baseline = pct("none")
    if baseline is not None:
        parts.append(f"The undefended baseline executes {baseline:.0f}% of attacks.")
    for config in configs:
        if config == "none":
            continue
        value = pct(config)
        if value is None or baseline is None:
            continue
        delta = baseline - value
        direction = "removes" if delta > 0 else "adds"
        parts.append(
            f"`{config}` executes {value:.0f}% ({direction} {abs(delta):.0f} points "
            "against the baseline)."
        )
    reached = (overall.get("full") or {}).get("reached_pct")
    executed = pct("full")
    if reached is not None and executed is not None and reached > executed:
        parts.append(
            f"Under `full`, {reached:.0f}% of attacks still persuade the model to "
            f"propose the malicious action but only {executed:.0f}% survive to an "
            "effect, which is the layered defence rather than the model resisting."
        )
    return " ".join(parts) or "_Not enough data for an ablation summary._"


def build(
    results_path: Path = RESULTS_PATH,
    report_path: Path = REPORT_PATH,
    summary_path: Path = SUMMARY_PATH,
    settings: Settings | None = None,
) -> Path:
    settings = settings or Settings()
    rows = load_results(results_path)
    present = [name for name in PRESET_NAMES if any(r["config"] == name for r in rows)]
    configs = present or list(PRESET_NAMES)

    asr_lines, asr_summary = asr_table(rows, configs)
    rule_lines, rule_summary = rules_table(rows, configs)
    errors = [r for r in rows if r.get("error")]

    body = [
        "# Doorman - results",
        "",
        f"- Generated: {datetime.now(UTC).isoformat(timespec='seconds')}",
        f"- Commit: `{_git_sha()}`",
        f"- Agent model: `{settings.agent_model}`",
        f"- Reader model: `{settings.reader_model}`",
        f"- Classifier threshold: {settings.classifier_threshold}",
        f"- Runs: {len(rows)}" + (f" ({len(errors)} errored)" if errors else ""),
        "",
        "## Attack success rate by family",
        "",
        "Cell is `executed% (reached%)`. **reached** means the model proposed the "
        "malicious action; **executed** means the effect exists in final state. The "
        "gap between them is what the defences removed.",
        "",
        *asr_lines,
        "",
        "> Reading note: where the orchestrator skips a phase outright (the taint "
        "gate), the model is never asked, so `reached` is false because the "
        "opportunity never arose - not because the model refused.",
        "",
        "## Rules fired",
        "",
        *rule_lines,
        "",
        "## Ablation",
        "",
        ablation_paragraph(asr_summary, configs),
        "",
    ]
    if errors:
        body += [
            "## Errors",
            "",
            *[f"- `{r['item_id']}` / `{r['config']}`: {r['error']}" for r in errors[:20]],
            "",
        ]

    Path(report_path).write_text("\n".join(body), encoding="utf-8")
    Path(summary_path).parent.mkdir(parents=True, exist_ok=True)
    Path(summary_path).write_text(
        json.dumps(
            {
                "generated": datetime.now(UTC).isoformat(timespec="seconds"),
                "commit": _git_sha(),
                "agent_model": settings.agent_model,
                "reader_model": settings.reader_model,
                "configs": configs,
                "asr": asr_summary,
                "rules_fired": rule_summary,
                "runs": len(rows),
                "errors": len(errors),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return Path(report_path)
