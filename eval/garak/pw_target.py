"""garak targets for Promptwall (used with garak's `function.Single` generator).

  unguarded(prompt) -> the same app WITHOUT Promptwall (system prompt + model, nothing else)
  guarded(prompt)   -> the app behind the full Promptwall gateway

The model comes from PROMPTWALL_BACKEND:
  anthropic  real Claude (PROMPTWALL_MODEL, needs ANTHROPIC_API_KEY)
  echo       a worst-case "obedient" model that returns the attacker's text verbatim, so any
             attack string that survives is the gateway's miss, not the model's ($0, offline)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from promptwall.backends import get_backend
from promptwall.gateway import Gateway, Request, Unguarded, load_policy
from promptwall.types import LLMResponse

ROOT = Path(__file__).resolve().parents[2]


class EchoBackend:
    name = "echo"

    def complete(self, system, messages, tools):
        return LLMResponse(messages[-1]["content"])


def _backend():
    name = os.environ.get("PROMPTWALL_BACKEND", "echo")
    return EchoBackend() if name == "echo" else get_backend(name)


_policy = load_policy(os.environ.get("PROMPTWALL_POLICY", ROOT / "policy.yaml"))
_backend_obj = None


def _b():
    global _backend_obj
    if _backend_obj is None:
        _backend_obj = _backend()
    return _backend_obj


def _run(app, prompt: str) -> list[str | None]:
    try:
        return [app.handle(Request(prompt)).text]
    except Exception as e:  # API errors are excluded from the score, not counted as a pass
        print(f"PW_GARAK_ERROR {type(e).__name__}: {e}", file=sys.stderr)
        return [None]


def unguarded(prompt: str, **_) -> list[str | None]:
    return _run(Unguarded(_policy, _b()), prompt)


def guarded(prompt: str, **_) -> list[str | None]:
    return _run(Gateway(_policy, _b()), prompt)
