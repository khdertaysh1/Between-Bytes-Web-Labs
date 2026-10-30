# HPP exercise validation · 2026-10-31

Scope: one additional hands-on Code exercise, not a replacement of existing labs.
Current catalog: 13 rooms/97 cases; Code has four. Release metadata: 0.12.1.

Local runtime: CPython 3.12.14/Linux, Node 24.22.1. Commands/results:

- `python tools/quality.py python`: 86 tests passed (77 retained, nine added).
- `python tools/quality.py sensitivity`: all three existing disposable payment/ownership/CSRF mutants detected.
- `npm ci --ignore-scripts --no-audit --no-fund`: installed locked development dependencies.
- `npx --no-install playwright install chromium`: failed in this environment because the downloaded archive was empty/invalid. No suite was skipped and no runner/workflow was weakened.
- `BB_BROWSER_PATH=/tmp/bb-headless/chromium python tools/quality.py browser`: all nine suites passed using a temporary Chromium 153 executable through the documented override. This executable is not a project dependency; CI retains its normal pinned Playwright Chromium install.
- `node --check academy.js`, `node --check studio.js`, Python compileall and `git diff --check`: passed.

Behavioral coverage includes ordered/encoded duplicate owner keys, reversed ordering,
valid repeated tags, identical owner duplicates, unknown/malformed/bounded input,
valid access and denied access with no returned record, unchanged exercise data,
matching evidence/flags/reset, real GET versus JSON-adapter parity, session/origin
and method guards. Existing full-HTTP contracts now exercise all 97 cases.

Browser coverage includes all 97 guided and manual-field workflows, GET editor mutation,
200/400 responses and body evidence, local Host restriction, request method/order,
replay/comparison, progressive hints, matching completion, bilingual layout and a
390×844 viewport without horizontal overflow. Arabic screenshot was visually reviewed.
Existing CSRF/CORS browser flows and all XSS observations/regressions passed as well.

The only old test-contract adjustments are the new 97-case total, version 0.12.1 and
explicit HPP status mapping. The new HPP browser assertions extend an already required
suite. No tests, assertions, required checks or CI jobs were removed/skipped.

Limits: no physical Android/Termux device was executed. HPP first/last choices are
explicit Python application policies; this does not validate a named proxy/framework.
GET and parsing are real local execution with synthetic read-only documents, and no
third-party sites are contacted. No browser-executed attack payload is used by HPP.
Final GitHub CI conclusions are recorded in the PR, independently of these local results.
