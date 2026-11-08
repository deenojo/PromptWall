"""Model backends behind the gateway. All map (system, messages, tools) -> LLMResponse.

- AnthropicBackend: Claude via the official SDK (ANTHROPIC_API_KEY)
- OllamaBackend:    a local open model, $0
- ScriptedBackend:  returns a fixed response. Used to simulate a *fully compromised* model in the
                    red-team eval, so the numbers measure the gateway, not the model's own safety.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Protocol

from promptwall.types import LLMResponse, ToolCall


class Backend(Protocol):
    name: str

    def complete(self, system: str, messages: list[dict], tools: list[dict]) -> LLMResponse: ...


class ScriptedBackend:
    name = "scripted"

    def __init__(self, response: LLMResponse | None = None):
        self.response = response or LLMResponse("ok")
        self.last_system: str | None = None
        self.last_messages: list[dict] | None = None

    def complete(self, system, messages, tools):
        self.last_system, self.last_messages = system, messages
        return self.response


class AnthropicBackend:
    def __init__(self, model: str | None = None, max_tokens: int = 1024):
        import anthropic

        self.client = anthropic.Anthropic()
        self.model = model or os.environ.get("PROMPTWALL_MODEL", "claude-haiku-5-5")
        self.max_tokens = max_tokens
        self.name = f"anthropic:{self.model}"

    def complete(self, system, messages, tools):
        kwargs = dict(model=self.model, max_tokens=self.max_tokens, system=system, messages=messages)
        if tools:
            kwargs["tools"] = tools
        resp = self.client.messages.create(**kwargs)
        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
        calls = [ToolCall(b.name, dict(b.input)) for b in resp.content if getattr(b, "type", "") == "tool_use"]
        return LLMResponse(text, calls)


class OllamaBackend:
    def __init__(self, model: str | None = None, host: str | None = None):
        self.model = model or os.environ.get("PROMPTWALL_OLLAMA_MODEL", "llama3.1")
        self.host = (host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")).rstrip("/")
        self.name = f"ollama:{self.model}"

    def complete(self, system, messages, tools):
        body = {"model": self.model, "stream": False,
                "messages": [{"role": "system", "content": system}, *messages]}
        if tools:
            body["tools"] = [{"type": "function", "function": {
                "name": t["name"], "description": t.get("description", ""), "parameters": t["input_schema"]}}
                for t in tools]
        req = urllib.request.Request(f"{self.host}/api/chat", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            msg = json.loads(r.read())["message"]
        calls = [ToolCall(c["function"]["name"], c["function"].get("arguments") or {}) for c in msg.get("tool_calls") or []]
        return LLMResponse(msg.get("content", ""), calls)


def get_backend(name: str) -> Backend:
    if name == "anthropic":
        return AnthropicBackend()
    if name == "ollama":
        return OllamaBackend()
    if name == "scripted":
        return ScriptedBackend()
    raise ValueError(f"unknown backend {name!r}")
