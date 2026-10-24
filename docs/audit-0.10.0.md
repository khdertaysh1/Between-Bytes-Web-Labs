# Release verification · 0.10.0

## Scope

The current interface contains 72 cases in nine labs. SSRF, CSRF, CORS and Open Redirect each have six cases. The former direct SSRF and redirect cases retain their IDs but move out of the code lab, which now contains three cases. The foundation UI and its static assets are deleted; supported legacy hashes resolve inside the current UI. `/foundations` returns a redirect to `/academy`.

## Expected request-policy outcomes

These are closed models, not network or cross-origin browser exploitation tests. The displayed POST is an actual request to the local decision API. Origin, session and DNS fields within its JSON are fixtures; nested response-header/preflight fields describe the modeled resource, not real HTTP headers sent by the browser.

| Lab | Vulnerable example | Fixed control | Fixed example | Evidence |
|---|---:|---:|---:|---|
| SSRF, six cases | 200 | 200 | 403 | Private fixture content only in vulnerable mode; blocked traces contain no fixture-read step |
| Open Redirect, six cases | 200 | 200 | 403 | Proposed external destination versus rejected destination; navigation always false |
| CSRF: missing, empty, session binding, origin exemption | 200 | 200 | 403 | Note update applies only when policy allows; rejection preserves state |
| CSRF: GET update | 200 | 200 | 405 | No state change after rejected method; Allow: POST |
| CSRF: content-type gap | 200 | 200 | 415 | Unsupported modeled form type does not update state |
| CORS, six cases | 200 | 200 | 200 | Private body readable only when the modeled policy grants permission; authentication is independently required |

CORS preflight is represented as 204/403 inside the policy result. A rejected preflight means a real browser would not send the subsequent request; the fixture GET status is described separately. No real OPTIONS or remote fetch is performed by these new cases. No SSRF DNS resolution, socket operation, file access or redirect navigation is performed.

## Verification performed

- 63 Python tests pass, including the complete explicit HTTP matrix across all 72 cases, malformed inputs, session isolation, payment state and legacy backend regression coverage.
- The academy browser suite completes all 72 cases with matching fixed evidence and usable controls, bilingual display, mobile layout and session isolation.
- The request-security browser suite checks all 24 workflows, independent six-case navigation, old-asset 404 responses, supported legacy links, English/Arabic display, mobile layout and loopback-only requests.
- Grouped navigation, all 16 payment HTTP outcomes, stale-result/error edge cases, and 36 XSS payload/control samples in both variants pass. The 72 XSS observations use isolated browser previews; the URL case checks href policy only.

A completion mark describes a local teaching exercise. It is not an external security finding, a certificate or evidence that a production application has no vulnerabilities.
