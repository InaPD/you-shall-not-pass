"""Manifest -> rendered attack files (spec 16.3).

The manifest is validated before anything is rendered, so a malformed corpus
fails loudly rather than producing a partial set that quietly skews a report.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

CORPUS_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = CORPUS_ROOT / "attacks" / "manifest.yaml"
OUT_DIR = CORPUS_ROOT / "attacks" / "out"
PAYLOAD_DIR = CORPUS_ROOT / "payloads"
PROFILE_DIR = CORPUS_ROOT / "profiles"

# family -> generator module. Adding a placement family is one entry plus a module.
GENERATORS = {
    "direct": "corpus.attacks.generators.direct",
    "hidden_text": "corpus.attacks.generators.hidden_text",
}

# Spec 16.4: a score-inflation oracle against an already-qualified profile proves
# nothing, so the pairing is rejected rather than silently reported.
SCORE_ORACLES = frozenset({"score_gte"})
UNSCORABLE_PROFILES = frozenset({"qualified_senior"})


class ManifestError(ValueError):
    pass


@dataclass(frozen=True)
class AttackSpec:
    id: str
    family: str
    placement: str
    payload: str
    target_profile: str
    oracle: str
    oracle_args: dict[str, Any]
    notes: str = ""

    @property
    def payload_path(self) -> Path:
        return PAYLOAD_DIR / f"{self.payload}.txt"

    @property
    def profile_path(self) -> Path:
        return PROFILE_DIR / f"{self.target_profile}.yaml"


def load_manifest(path: Path = MANIFEST_PATH) -> list[AttackSpec]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    specs = [AttackSpec(**entry) for entry in raw]
    validate(specs)
    return specs


def validate(specs: list[AttackSpec]) -> None:
    seen: set[str] = set()
    for spec in specs:
        if spec.id in seen:
            raise ManifestError(f"duplicate attack id {spec.id}")
        seen.add(spec.id)

        if spec.oracle in SCORE_ORACLES and spec.target_profile in UNSCORABLE_PROFILES:
            raise ManifestError(
                f"{spec.id}: oracle {spec.oracle!r} against {spec.target_profile!r} is "
                "not meaningful - a qualified candidate scoring high proves nothing "
                "(spec 16.4)"
            )
        if spec.family not in GENERATORS:
            raise ManifestError(f"{spec.id}: no generator for family {spec.family!r}")
        if not spec.payload_path.is_file():
            raise ManifestError(f"{spec.id}: missing payload {spec.payload_path}")
        if not spec.profile_path.is_file():
            raise ManifestError(f"{spec.id}: missing profile {spec.profile_path}")

        module = importlib.import_module(GENERATORS[spec.family])
        if spec.placement not in module.PLACEMENTS:
            raise ManifestError(
                f"{spec.id}: placement {spec.placement!r} not supported by "
                f"family {spec.family!r} (has {', '.join(module.PLACEMENTS)})"
            )


def build_one(spec: AttackSpec, out_dir: Path = OUT_DIR) -> Path:
    profile = yaml.safe_load(spec.profile_path.read_text(encoding="utf-8"))
    payload = spec.payload_path.read_text(encoding="utf-8").strip()
    module = importlib.import_module(GENERATORS[spec.family])
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    return module.build(profile, payload, Path(out_dir), spec.id, placement=spec.placement)


def build_all(
    manifest: Path = MANIFEST_PATH, out_dir: Path = OUT_DIR
) -> list[tuple[AttackSpec, Path]]:
    return [(spec, build_one(spec, out_dir)) for spec in load_manifest(manifest)]
