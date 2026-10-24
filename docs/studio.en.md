# Hands-on workspace · 0.11.0

The established visual design, explanations and nine-lab navigation remain. All 72 cases now have a workspace with typed fields, actual application POST history, replay, comparison, an HTTP editor, encoding tools and effect inspection. The case-header practice link jumps to the tools without changing the scenario hash.

## Fields, requests and effects

Edit field values and types, or omit fields entirely. A NoSQL password can be changed from string to JSON. Field submissions use the existing case engine; responses are not invented by the UI. Select one recorded POST to edit/replay, or two to compare their input and response. Replay performs the operation again and can mutate state. This history is not a full browser proxy: it records submissions from the case editors, while browser-practice requests have a separate server trace.

The HTTP editor accepts the current case’s POST route and variant, Content-Type, and X-Forwarded-For in rate-limit exercises. It cannot spoof browser-managed Cookie or Origin, or send requests to arbitrary targets. Wrong input and content types retain actual error statuses. URL/HTML/Base64 encoding tools can apply transformed text to a selected field; Base64 supports UTF-8.

XSS inspection uses an actual isolated-frame DOM snapshot and execution/error messages. The URL case inspects href policy only. Payment uses persisted order/ledger/entitlement state, access control exposes actor/resource ownership, and rate-limit results distinguish 401 verification failures from 429 throttling. SSRF transport and redirect navigation remain closed models with explicit traces and destination decisions.

## Real browser practice

In CSRF/CORS open Browser & results and start the browser sessions. Researcher and lab-user accounts have different scoped HttpOnly synthetic session cookies. Use the account form normally, then write HTML/JavaScript in the page editor or load an editable starter. Run the authored page on the second loopback origin and perform its action yourself.

The six live CSRF cases cover missing/empty tokens, cross-session token binding, origin exemptions, state-changing GET and text/plain parsing. Fixed variants reject before mutating account state and retain normal same-origin updates. The live origin exemption intentionally ignores the port in its prefix trust rule; the hostname-prefix example remains a separate JSON-policy fixture.

A no-cors response is opaque: the authored page does not know its real HTTP status. Inspect the server trace and independent account state for the outcome. Browser-practice evidence is separate from JSON-policy completion marks.

The companion CORS exercise demonstrates actual credentialed origin reflection: the vulnerable response is readable; the fixed response remains HTTP 200 but the browser denies cross-origin access. It does not claim to exercise the six JSON origin-pattern scenarios in real browsers.

Resetting browser practice rotates target URLs, session cookies and tokens, clears account state/logs, and expires old pages. Delayed requests to the previous round cannot modify the new round. Your source remains editable; update its URLs or load a fresh starter before running it again.

## Boundaries and persistence

Both ports are loopback and same-site but cross-origin. This is not a SameSite-bypass demonstration. Learner pages are sandboxed on the separate origin with CSP restricting fetch, forms and resources to permitted local services; console messages are checked against frame, origin and run nonce. There are no production accounts, external scans or payment providers.

Language changes preserve case inputs, mode and unsaved reasoning. Tool history and page drafts are in page memory and do not survive a reload. Save your conclusion/export evidence before closing. Navigation or variant changes cancel active previews.
