"""Synthetic authorization lessons and isolated browser rendering documents."""
import html
import json
import re

PREVIEW_CSP = ("sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; "
               "style-src 'none'; connect-src 'none'; img-src 'none'; form-action 'none'; "
               "base-uri 'none'; frame-src 'none'; frame-ancestors 'self'")
INVOICES = {
    "1001": {"id": "1001", "owner": "alice", "amount": "24.00", "note": "Alice training invoice"},
    "1002": {"id": "1002", "owner": "bob", "amount": "79.00", "note": "Bob synthetic private invoice"},
}


def access_lesson(kind, mode, form):
    if mode not in {"vulnerable", "fixed"}:
        return 404, {"error": "Unknown mode"}
    if kind == "idor":
        # Actor is server-defined, never taken from a user-supplied identity field.
        invoice = INVOICES.get(form.get("resource", [""])[0])
        if invoice is None:
            return 404, {"error": "Invoice not found", "actor": "alice"}
        if mode == "fixed" and invoice["owner"] != "alice":
            return 403, {"error": "Object access denied", "actor": "alice"}
        return 200, {"actor": "alice", "invoice": invoice.copy()}
    if kind == "edge403":
        layer = form.get("layer", ["edge"])[0]
        if layer not in {"edge", "origin"}:
            return 400, {"error": "Choose the synthetic edge or origin route"}
        if layer == "edge" or mode == "fixed":
            return 403, {"error": "Access denied", "layer": layer, "simulation": True}
        return 200, {"layer": layer, "simulation": True,
                     "resource": "Synthetic admin page", "actor": "anonymous",
                     "cause": "Origin forgot to enforce authorization"}
    return 404, {"error": "Unknown lesson"}


def preview_document(kind, mode, value, token):
    if kind not in {"reflected-xss", "dom-xss"} or mode not in {"vulnerable", "fixed"}:
        raise ValueError("Unknown preview")
    if not re.fullmatch(r"[a-f0-9]{32}", token) or len(value) > 1000:
        raise ValueError("Invalid preview input")
    # q is never interpolated into JavaScript. Only escaped or deliberately raw HTML.
    prelude = f'''<!doctype html><html><head><meta charset="utf-8"><title>Isolated XSS exercise</title></head><body>
<script>
const token = {json.dumps(token)};
function report(type, extra) {{ parent.postMessage({{type, token, ...extra}}, '*'); }}
window.alert = value => report('bb-executed', {{value: String(value).slice(0,100)}});
function rendered() {{ report('bb-rendered', {{text: document.getElementById('output').textContent, images: document.getElementById('output').querySelectorAll('img').length}}); }}
</script><h3>Training search results</h3>'''
    if kind == "reflected-xss":
        output = value if mode == "vulnerable" else html.escape(value)
        return prelude + '<div id="output">' + output + '</div><script>rendered();</script></body></html>'
    assignment = "output.innerHTML = event.data.value;" if mode == "vulnerable" else "output.textContent = event.data.value;"
    return prelude + f'''<div id="output"></div><script>
window.addEventListener('message', event => {{
    if (event.source !== parent || event.data?.token !== token || typeof event.data.value !== 'string' || event.data.value.length > 1000) return;
    const output = document.getElementById('output');
    {assignment}
    rendered();
}});
report('bb-ready', {{}});
</script></body></html>'''
