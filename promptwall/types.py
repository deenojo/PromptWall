"""Shared types: what a guard sees and what it decides."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Action(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"   # allowed after modification
    BLOCK = "block"


@dataclass
class Finding:
    guard: str
    kind: str          # e.g. "prompt_injection", "pii:email", "secret:aws_key"
    detail: str
    score: float = 1.0
    span: tuple[int, int] | None = None


@dataclass
class Verdict:
    action: Action = Action.ALLOW
    findings: list[Finding] = field(default_factory=list)
    text: str | None = None  # modified text when action == REDACT

    def merge(self, other: "Verdict") -> "Verdict":
        order = {Action.ALLOW: 0, Action.REDACT: 1, Action.BLOCK: 2}
        action = max(self.action, other.action, key=lambda a: order[a])
        return Verdict(action, self.findings + other.findings, other.text if other.text is not None else self.text)


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
