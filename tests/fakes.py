"""A scripted stand-in for the Anthropic client.

Spec 19 requires the whole suite to run in CI with no API key. Every test that
drives the agent loop scripts the model's tool calls through this, so the loop,
the router and the policy layer are exercised without a network call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FakeBlock:
    type: str
    id: str = ""
    name: str = ""
    input: dict[str, Any] = field(default_factory=dict)
    text: str = ""


@dataclass
class FakeUsage:
    input_tokens: int = 1000
    output_tokens: int = 50


@dataclass
class FakeResponse:
    content: list[FakeBlock]
    stop_reason: str = "tool_use"
    usage: FakeUsage = field(default_factory=FakeUsage)


def tool_use(*calls: tuple[str, dict[str, Any]]) -> FakeResponse:
    """One response proposing each (tool_name, input) in order."""
    return FakeResponse(
        content=[
            FakeBlock(type="tool_use", id=f"tu_{index}", name=name, input=args)
            for index, (name, args) in enumerate(calls)
        ]
    )


def text(message: str = "Done.") -> FakeResponse:
    return FakeResponse(content=[FakeBlock(type="text", text=message)], stop_reason="end_turn")


class FakeMessages:
    def __init__(self, script: list[FakeResponse]) -> None:
        self.script = list(script)
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> FakeResponse:
        self.calls.append(kwargs)
        if not self.script:
            return text()  # model stops calling tools once the script runs out
        return self.script.pop(0)


class FakeClient:
    """Drop-in for `anthropic.Anthropic()`."""

    def __init__(self, *script: FakeResponse) -> None:
        self.messages = FakeMessages(list(script))

    @property
    def calls(self) -> list[dict[str, Any]]:
        return self.messages.calls

    @property
    def systems(self) -> list[str]:
        return [call.get("system", "") for call in self.messages.calls]
