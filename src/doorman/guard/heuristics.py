"""Advisory heuristics, CLS-101 and CLS-102 (spec 10.2).

These FLAG and nothing else. They never change taint and never block, and that is
the point of them: they demonstrate that phrase-matching is not the control. The
report shows what they would have caught next to what the structural layers
actually stopped.

The same regexes back OUT-005 on outbound text.
"""

from __future__ import annotations

import re

# CLS-101: imperatives addressed to the system rather than to a human reader.
INSTRUCTION_PATTERNS = (
    re.compile(r"\b(ignore|disregard|override|bypass|skip)\b[^.]{0,40}\b"
               r"(previous|prior|above|earlier|all)\b", re.I),
    re.compile(r"\b(system|assistant|ai|model|screening (assistant|agent|system))\b"
               r"[^.]{0,30}\b(must|should|shall|will|please)\b", re.I),
    re.compile(r"\byou (are|must|should|will) (now|instead|always)\b", re.I),
    re.compile(r"\b(new|updated|revised) (instructions?|rules?|policy|directive)\b", re.I),
    re.compile(r"\b(do not|don't|never) (tell|mention|reveal|disclose|inform)\b", re.I),
    re.compile(r"\bset (the )?(score|status|rating)\b[^.]{0,20}\b(to|at)\b", re.I),
)

# CLS-102: forged delimiters and role markers in untrusted text.
DELIMITER_PATTERNS = (
    re.compile(r"^\s*(SYSTEM|ASSISTANT|USER)\s*:", re.I | re.M),
    re.compile(r"</?(tool_result|tool_use|function_results?|system)\b", re.I),
    re.compile(r'"role"\s*:\s*"(assistant|system)"', re.I),
    re.compile(r"\[/?INST\]|<\|im_(start|end)\|>|<\|endoftext\|>", re.I),
    re.compile(r"</?untrusted_data\b", re.I),
)


def _first_match(patterns, text: str) -> str | None:
    for pattern in patterns:
        found = pattern.search(text)
        if found:
            return found.group(0)
    return None


def instruction_like(text: str) -> str | None:
    """CLS-101 / OUT-005. Returns the matched fragment, or None."""
    return _first_match(INSTRUCTION_PATTERNS, text)


def forged_delimiter(text: str) -> str | None:
    """CLS-102. Returns the matched fragment, or None."""
    return _first_match(DELIMITER_PATTERNS, text)


def evaluate(text: str) -> list[tuple[str, str]]:
    """Every advisory rule that fires, as (rule_id, matched fragment)."""
    hits: list[tuple[str, str]] = []
    instruction = instruction_like(text)
    if instruction:
        hits.append(("CLS-101", instruction))
    delimiter = forged_delimiter(text)
    if delimiter:
        hits.append(("CLS-102", delimiter))
    return hits
