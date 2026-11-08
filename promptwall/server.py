"""HTTP API: run the gateway as a service in front of your LLM feature.

  PROMPTWALL_BACKEND=anthropic uvicorn promptwall.server:app --port 8080
  curl -s localhost:8080/v1/guarded-chat -H 'content-type: application/json' \
       -d '{"user": "Where is order ORD-123456?"}'
"""

from __future__ import annotations

import os

from fastapi import FastAPI
from pydantic import BaseModel, Field

from promptwall.backends import get_backend
from promptwall.gateway import Gateway, Request, load_policy

app = FastAPI(title="Promptwall", version="0.1.0")
_gateway: Gateway | None = None


def gateway() -> Gateway:
    global _gateway
    if _gateway is None:
        _gateway = Gateway(
            load_policy(os.environ.get("PROMPTWALL_POLICY", "policy.yaml")),
            get_backend(os.environ.get("PROMPTWALL_BACKEND", "scripted")),
            os.environ.get("PROMPTWALL_AUDIT", "logs/audit.jsonl"),
        )
    return _gateway


class ChatIn(BaseModel):
    user: str = Field(max_length=8000)
    documents: list[str] = Field(default_factory=list, max_length=20)
    route: str = "default"


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/v1/guarded-chat")
def guarded_chat(body: ChatIn):
    return gateway().handle(Request(body.user, body.documents, body.route)).as_dict()
