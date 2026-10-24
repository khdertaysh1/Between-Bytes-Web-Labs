# Release verification · 0.11.0

The established visual design and lesson structure remain. Nine labs retain 72 cases. The new manual workspace is available in every case; this release does not convert every fixture into a full target VM.

## What changed

- Typed editable fields, optional-field omission and actual case-engine submissions across all 72 cases.
- Application POST history, selected-request editing/replay and colored request/response comparison. This is editor history, not a full browser proxy.
- A bounded HTTP editor for the current case, with supported Content-Type/X-Forwarded-For editing and rejection of arbitrary hosts, routes, duplicate headers and browser-managed headers.
- URL/HTML/Base64 transforms, UTF-8 handling, field insertion, actual XSS sink DOM snapshots and runtime event/error inspection.
- Real two-origin CSRF practice covering all six CSRF cases, with independent researcher/victim scoped HttpOnly cookies, editable authored HTML/JavaScript, live account state and actual server traces.
- A real credentialed CORS origin-reflection read/block exercise. This companion does not claim real-browser coverage of the six JSON origin-pattern cases.

## Evidence and boundaries

The existing JSON policy cases and their completion marks remain separate from real browser practice. Browser no-cors responses are opaque; the UI takes their status from server traces and their effect from persisted account state. CORS fixed responses can remain HTTP 200 while the browser denies access to the body.

Both browser-practice ports are loopback, cross-origin but same-site. This does not demonstrate SameSite bypass. The live CSRF origin exemption intentionally ignores the port; the hostname-prefix fixture remains in JSON. SSRF and redirect transport/navigation remain closed models. No production account, payment provider, external scanner or general shell is introduced.

Authored pages are served on the second origin in a sandbox, with CSP restricting fetch, forms and resources. Console events require the correct source frame, origin and per-run nonce. Account notes are escaped in the target page. Server traces omit actual session tokens and cookie values.

## Verification

- **69 Python tests:** complete 72-case HTTP matrix, payment/resource state, input validation, session isolation and legacy backend regressions, plus studio cookie scoping, token/session binding, rejected-write invariants, CORS headers/statuses, authored-document limits, reset expiry and stale-round URL rejection.
- **72 manual field workflows:** usable fixed control, vulnerable example, matching fixed example, expected completion/evidence and actual request history. All nine labs are exercised on mobile.
- **72 existing academy workflows:** regression coverage for the prior JSON interface, bilingual labels, browser-assisted XSS, fixed controls, local marks and isolated sessions.
- **Six live CSRF workflows:** actual second-origin weak requests update only the intended victim account; fixed variants reject with 403/405/415; same-origin fixed controls still save correctly.
- **Actual CORS browser observations:** weak read exposes the private fixture; fixed read is blocked by the browser while the server returns 200. Learner-authored JS executes and its console appears in the workspace.
- Request replay/comparison, edited Content-Type producing actual 415, arbitrary-host/browser-managed-header rejection, invalid URL decoding, UTF-8 Base64 round trips, and actual DOM inspection.
- Language switching preserves input, mode and unsaved reasoning. Pending submissions lock newly navigated controls; stale results do not populate another case. The practice jump link preserves the selected scenario.
- Grouped navigation, 24 request-security policy workflows, all 16 payment outcomes, stale-preview/error regressions, and **72 XSS payload/control browser observations** remain covered by the existing suites.

## Corrections made during this work

Language changes previously reset active inputs and unsaved reasoning. These values now survive translation. Payment readbacks are guarded against stale case/mode results. Browser reset rotates IDs/cookies/tokens so delayed requests and old documents cannot affect a fresh round. Active authored previews are invalidated on navigation/variant changes, with frame/origin/nonce checks on console messages.

Tool history and page drafts are bounded page-memory state, not durable cloud storage or an exam boundary. Browser practice and policy-model completion are explicitly distinct. The earlier [0.10.0 report](audit-0.10.0.md) documents the preceding release.
