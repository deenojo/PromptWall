"""Prompt-injection detection for user input and retrieved (indirect) content.

Layered, cheap-first:
  1. Normalization: Unicode NFKC, strip zero-width and Unicode "tag" characters, which are used
     to hide instructions from human reviewers.
  2. Signature rules: weighted regexes for known attack families (instruction override,
     role/authority spoofing, delimiter break-out, prompt extraction, exfil setups).
  3. Obfuscation checks: decode base64 / hex blobs and re-scan them.
The score is the sum of rule weights; the policy sets the block threshold. An optional
model-based classifier can be plugged in for the residual risk regexes can't catch.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

from promptwall.types import Action, Finding, Verdict

INVISIBLE = re.compile("[​-‏⁠-⁤﻿\U000e0000-\U000e007f]")

RULES: list[tuple[str, float, re.Pattern]] = [
    ("override", 0.6, re.compile(
        r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(previous|prior|above|earlier|all|your|system)\b.{0,30}"
        r"\b(instructions?|rules?|prompts?|directives?|guidelines?|polic(y|ies))\b", re.I | re.S)),
    ("new_instructions", 0.4, re.compile(r"\b(new|updated|real|actual)\s+(instructions?|rules|system prompt)\b\s*[:\-]", re.I)),
    ("role_spoof", 0.5, re.compile(
        r"(^|\n)\s*(system|assistant|developer|admin)\s*[:>\]]|<\|?(system|im_start|im_end)\|?>|\[(system|inst)\]", re.I)),
    ("authority", 0.4, re.compile(
        r"\b(as (an?|the) (admin|administrator|developer|system)|(anthropic|openai|security team|it department)"
        r"\s+(override|says|requires|authori[sz]es)|developer mode|jailbreak|dan mode)\b", re.I)),
    ("prompt_extraction", 0.6, re.compile(
        r"\b(reveal|print|show|repeat|output|tell me|what (is|are))\b.{0,40}\b(your|the)\s+"
        r"(system prompt|instructions|initial prompt|hidden (rules|prompt)|developer message)", re.I | re.S)),
    ("delimiter_breakout", 0.5, re.compile(r"</?\s*(untrusted|document|context|data|user_input)[^>]*>", re.I)),
    ("exfil_setup", 0.5, re.compile(
        r"!\[[^\]]*\]\(\s*https?://[^)]*(\{|%7B|\?[^)]*=)|\b(send|post|upload|forward|exfiltrate)\b.{0,40}"
        r"\b(to|at)\b.{0,20}(https?://|\S+@\S+\.\w+)", re.I | re.S)),
    ("tool_coercion", 0.4, re.compile(
        r"\b(call|use|invoke|run|execute)\b.{0,20}\b(the\s+)?(tool|function|send_email|run_sql|delete|transfer)\b.{0,60}"
        r"\b(now|immediately|without (asking|confirmation))", re.I | re.S)),
]

B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){16,}\b")


def normalize(text: str) -> tuple[str, int]:
    """Return (normalized text, number of invisible characters removed)."""
    t = unicodedata.normalize("NFKC", text or "")
    cleaned, n = INVISIBLE.subn("", t)
    return cleaned, n


def _decoded_blobs(text: str) -> list[str]:
    out = []
    for m in B64.finditer(text):
        try:
            raw = base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4), validate=False)
            s = raw.decode("utf-8")
            if sum(c.isprintable() for c in s) / max(len(s), 1) > 0.9:
                out.append(s)
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
    for m in HEX.finditer(text):
        try:
            s = bytes.fromhex(m.group(0)).decode("utf-8")
            if s.isprintable():
                out.append(s)
        except (ValueError, UnicodeDecodeError):
            pass
    return out


def score(text: str, source: str = "user") -> tuple[float, list[Finding]]:
    norm, hidden = normalize(text)
    findings: list[Finding] = []
    total = 0.0
    if hidden:
        w = 0.5
        total += w
        findings.append(Finding("injection", "prompt_injection:invisible_chars", f"{hidden} hidden characters ({source})", w))
    for name, weight, rx in RULES:
        m = rx.search(norm)
        if m:
            total += weight
            findings.append(Finding("injection", f"prompt_injection:{name}", f"{source}: …{m.group(0)[:80]}…", weight, m.span()))
    for blob in _decoded_blobs(norm):
        s, inner = score(blob, source + "/decoded")
        if s:
            total += s + 0.2  # hiding it is itself a signal
            findings.append(Finding("injection", "prompt_injection:encoded", f"encoded payload in {source}", 0.2))
            findings += inner
    return round(total, 2), findings


def check(text: str, threshold: float, source: str = "user") -> Verdict:
    s, findings = score(text, source)
    return Verdict(Action.BLOCK if s >= threshold else Action.ALLOW, findings if s else [])
