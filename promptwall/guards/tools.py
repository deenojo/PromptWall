"""Tool-call policy (OWASP LLM06, excessive agency).

Every tool call the model proposes is checked *before* the app executes it:
  - allowlist: unknown tools are refused
  - argument schema: required/typed fields, nothing extra
  - argument rules: e.g. email recipients only to allowed domains, SQL read-only, URL host allowlist
  - approval: high-impact tools are never auto-executed; they come back as "needs_approval"
  - taint: if untrusted content (retrieved docs) was in the context, side-effecting tools
    require approval even if they'd normally run
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from promptwall.types import Finding, ToolCall

SQL_WRITE = re.compile(r"\b(insert|update|delete|drop|alter|create|truncate|grant|revoke|merge|replace)\b", re.I)


@dataclass
class ToolDecision:
    call: ToolCall
    decision: str  # "allow" | "needs_approval" | "deny"
    findings: list[Finding] = field(default_factory=list)


def _type_ok(value, t: str) -> bool:
    return {"string": isinstance(value, str), "integer": isinstance(value, int) and not isinstance(value, bool),
            "number": isinstance(value, (int, float)) and not isinstance(value, bool),
            "boolean": isinstance(value, bool)}.get(t, True)


def check(call: ToolCall, policy: dict, tainted: bool) -> ToolDecision:
    tools = policy.get("tools", {})
    spec = tools.get(call.name)
    if spec is None:
        return ToolDecision(call, "deny", [Finding("tools", "tool:not_allowlisted", call.name)])
    findings: list[Finding] = []
    args = call.arguments or {}
    schema = spec.get("args", {})
    for name, rule in schema.items():
        if rule.get("required") and name not in args:
            findings.append(Finding("tools", "tool:missing_arg", f"{call.name}.{name}"))
        elif name in args and not _type_ok(args[name], rule.get("type", "string")):
            findings.append(Finding("tools", "tool:bad_type", f"{call.name}.{name}"))
    extra = set(args) - set(schema)
    if extra:
        findings.append(Finding("tools", "tool:unexpected_args", f"{call.name}: {sorted(extra)}"))

    for name, rule in schema.items():
        v = args.get(name)
        if not isinstance(v, str):
            continue
        if rule.get("max_len") and len(v) > rule["max_len"]:
            findings.append(Finding("tools", "tool:arg_too_long", f"{call.name}.{name}"))
        if rule.get("email_domains"):
            dom = v.rsplit("@", 1)[-1].lower() if "@" in v else ""
            if dom not in [d.lower() for d in rule["email_domains"]]:
                findings.append(Finding("tools", "tool:recipient_not_allowed", f"{call.name}.{name}={dom or v}"))
        if rule.get("url_hosts"):
            host = (urlparse(v).hostname or "").lower()
            if not any(host == h or host.endswith("." + h) for h in rule["url_hosts"]):
                findings.append(Finding("tools", "tool:url_not_allowed", f"{call.name}.{name} host={host}"))
        if rule.get("sql_read_only") and (SQL_WRITE.search(v) or ";" in v.strip().rstrip(";")):
            findings.append(Finding("tools", "tool:sql_write_or_stacked", f"{call.name}.{name}"))
        if rule.get("pattern") and not re.fullmatch(rule["pattern"], v):
            findings.append(Finding("tools", "tool:pattern_mismatch", f"{call.name}.{name}"))

    if findings:
        return ToolDecision(call, "deny", findings)
    if spec.get("requires_approval"):
        return ToolDecision(call, "needs_approval", [Finding("tools", "tool:approval_required", call.name)])
    if tainted and spec.get("side_effects"):
        return ToolDecision(call, "needs_approval",
                            [Finding("tools", "tool:tainted_context", f"{call.name} after untrusted content")])
    return ToolDecision(call, "allow")
