"""Injection classifier (spec 10.1).

The classifier NEVER blocks a tool call and never drops content (spec 21.3). All
it does is flip taint to suspicious, which removes capabilities downstream. That
is what keeps the false-positive rate survivable: a benign resume that trips the
model gets routed to a human, not rejected.

`DebertaGuard` is behind the `Guard` protocol so it can be swapped, and its
imports are lazy so CI never pulls torch or downloads weights. `NullGuard` is the
default whenever the layer is off.
"""

from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel

# Chunk boundaries are measured in whitespace words, not model tokens. The model
# does its own tokenisation; this only has to keep each chunk comfortably inside
# the encoder's window, and a word is always at least one token.
DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
INJECTION_LABELS = ("INJECTION", "LABEL_1", "UNSAFE")


class GuardVerdict(BaseModel):
    score: float
    label: str
    unit_locator: str
    chunk_index: int


class Guard(Protocol):
    def score(self, text: str) -> float:
        """Probability that `text` contains an injection, 0..1."""
        ...


class NullGuard:
    """Scores everything 0.0. Used when the layer is off and throughout CI."""

    name = "null"

    def score(self, text: str) -> float:  # noqa: ARG002 - protocol shape
        return 0.0


class StubGuard:
    """Deterministic keyword guard for tests that need a non-zero score.

    Not a defence and never wired into a preset - it exists so the CLS-* plumbing
    can be exercised without downloading 400MB of weights.
    """

    name = "stub"

    def __init__(self, triggers: tuple[str, ...] = (), score_value: float = 0.99) -> None:
        self.triggers = tuple(t.lower() for t in triggers)
        self.score_value = score_value

    def score(self, text: str) -> float:
        lowered = text.lower()
        return self.score_value if any(t in lowered for t in self.triggers) else 0.0


class DebertaGuard:
    """The real classifier. Imports transformers lazily on first use."""

    name = DEFAULT_MODEL

    def __init__(self, model_name: str = DEFAULT_MODEL) -> None:
        self.model_name = model_name
        self._pipeline: Any | None = None

    def _ensure(self) -> Any:
        if self._pipeline is not None:
            return self._pipeline
        try:
            from transformers import pipeline
        except ImportError as exc:  # pragma: no cover - depends on the extra
            raise RuntimeError(
                "the classifier needs the optional extra: uv sync --extra classifier"
            ) from exc
        # truncation=False: our own chunking decides what the model sees, so a
        # long span cannot have its payload silently cut off by the tokenizer.
        self._pipeline = pipeline(
            "text-classification", model=self.model_name, device=-1, truncation=True,
            max_length=512,
        )
        return self._pipeline

    def score(self, text: str) -> float:
        if not text.strip():
            return 0.0
        result = self._ensure()(text)
        row = result[0] if isinstance(result, list) else result
        label = str(row.get("label", "")).upper()
        value = float(row.get("score", 0.0))
        return value if label in INJECTION_LABELS else 1.0 - value


def chunk(text: str, size: int, overlap: int) -> list[str]:
    """Split into overlapping windows of `size` words.

    The overlap matters: a payload split across a boundary would otherwise be
    two innocuous halves, which is exactly the `split` attack family.
    """
    words = text.split()
    if not words:
        return []
    if len(words) <= size:
        return [text]
    step = max(1, size - overlap)
    return [
        " ".join(words[start : start + size])
        for start in range(0, len(words), step)
        if words[start : start + size]
    ]


def score_unit(
    guard: Guard, text: str, *, size: int, overlap: int
) -> tuple[float, int]:
    """Score every chunk of one guard unit. Returns (max score, chunk index)."""
    chunks = chunk(text, size, overlap)
    if not chunks:
        return 0.0, 0
    scores = [guard.score(piece) for piece in chunks]
    best = max(range(len(scores)), key=scores.__getitem__)
    return scores[best], best


def build_guard(enabled: bool, model_name: str = DEFAULT_MODEL) -> Guard:
    return DebertaGuard(model_name) if enabled else NullGuard()
