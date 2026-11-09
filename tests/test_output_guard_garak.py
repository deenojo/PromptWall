"""Regressions for output-handling gaps found by the garak red team (eval/garak/)."""

from promptwall.guards import output


def _out(t, domains=("docs.example.com",)):
    v = output.check(t, list(domains))
    return v.text if v.text is not None else t, [f.kind for f in v.findings]


def test_javascript_link_is_not_treated_as_relative():
    text, kinds = _out("[click](javascript:alert(1))")
    assert "javascript:" not in text and "exfil:link" in kinds


def test_any_html_tag_is_escaped_including_event_handlers():
    text, _ = _out('ok `"\'><img src=xxx:x onerror=alert(1)> <div onclick="x()">hi</div>')
    assert "<img" not in text and "<div" not in text and "&lt;div" in text


def test_bare_script_schemes_are_defanged():
    text, kinds = _out("javascript:prompt(document.cookie) and data:text/html;base64,PHN")
    assert "javascript:" not in text and "data:text/html" not in text and "unsafe_scheme" in kinds


def test_terminal_escape_sequences_removed():
    text, kinds = _out("Hello \x1b[32mGREEN\x1b[0m\x07 \x1b]8;;https://evil.example/\x07link\x1b]8;;\x07 \x9b")
    assert "\x1b" not in text and "\x9b" not in text and "\x07" not in text and "terminal_escape" in kinds


def test_benign_text_untouched():
    t = "Order ORD-1 ships Tuesday.\n- 2 < 3 and 5 > 4\n- see [docs](https://docs.example.com/x)\tdone"
    assert _out(t) == (t, [])
