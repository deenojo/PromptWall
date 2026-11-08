"""PII and secret detection, with redaction.

Used in both directions:
  - inbound: redact before user text reaches a third-party model (data minimization)
  - outbound: catch the model leaking PII, credentials or the system-prompt canary
Credit cards are Luhn-checked to keep false positives down.
"""

from __future__ import annotations

import re

from promptwall.types import Action, Finding, Verdict

PATTERNS: dict[str, re.Pattern] = {
    "pii:email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "pii:ssn": re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    "pii:phone": re.compile(r"(?<!\d)(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)"),
    "pii:credit_card": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "secret:aws_access_key": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "secret:github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "secret:anthropic_key": re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
    "secret:openai_key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b"),
    "secret:private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "secret:jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
}


def luhn_ok(digits: str) -> bool:
    d = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def find(text: str, kinds: set[str] | None = None) -> list[Finding]:
    out: list[Finding] = []
    for kind, rx in PATTERNS.items():
        if kinds is not None and kind not in kinds and kind.split(":")[0] + ":*" not in kinds:
            continue
        for m in rx.finditer(text or ""):
            if kind == "pii:credit_card" and not luhn_ok(m.group(0)):
                continue
            out.append(Finding("sensitive", kind, f"{kind} at {m.start()}", 1.0, m.span()))
    return out


def redact(text: str, findings: list[Finding]) -> str:
    # Replace right-to-left so earlier spans stay valid; skip overlaps.
    spans = sorted({f.span: f.kind for f in findings if f.span}.items(), key=lambda x: -x[0][0])
    out, last_start = text, len(text) + 1
    for (start, end), kind in spans:
        if end > last_start:
            continue
        out = out[:start] + f"[{kind.split(':')[1].upper()}]" + out[end:]
        last_start = start
    return out


def check(text: str, *, mode: str, kinds: set[str] | None = None) -> Verdict:
    """mode: 'redact' (replace and allow) or 'block'."""
    findings = find(text, kinds)
    if not findings:
        return Verdict()
    if mode == "block":
        return Verdict(Action.BLOCK, findings)
    return Verdict(Action.REDACT, findings, redact(text, findings))


def check_canary(text: str, canary: str) -> Verdict:
    if canary and canary in (text or ""):
        return Verdict(Action.BLOCK, [Finding("sensitive", "leak:system_prompt_canary", "system prompt canary in output")])
    return Verdict()
