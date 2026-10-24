# Hands-on practice

Version 0.4 separates this practice from point-bearing practical assessments; see [course progression](course.en.md).

Seven local lessons now have a manual workbench. Open a lesson, choose the second tab, start/reset the challenge, edit its inputs, and send individual requests. The checklist advances from observed evidence rather than watching the automatic demonstration. Hints reveal progressively. Evidence can be downloaded as JSON. A round is bounded to 60 submissions; starting a round resets server counters/mail across all lessons. Progress is client-side educational state, not a tamper-resistant score or certification.

- **Enumeration:** existing and missing account in vulnerable mode, then matching 202/body for both in fixed mode.
- **Rate limit:** observe 429 first, then change the synthetic forwarded identity. Vulnerable returns 401; fixed remains 429. No real login or password guessing exists.
- **Mail abuse:** four requests per mode, four in-memory messages versus one during the cooldown. No SMTP.
- **IDOR:** server fixes the synthetic actor to Alice. Read invoice 1001, change resource to Bob's 1002, then verify fixed denies Bob and still permits Alice. Spoofing an actor field does not change server identity.
- **Reflected XSS:** type a local payload invoking `alert('BB-LAB')`; the local server reflects it into an isolated preview. Fixed escapes the HTML text context. Show the same input as literal text after the fix.
- **DOM XSS:** input moves from the parent workbench via postMessage to innerHTML (vulnerable) or textContent (fixed). The payload never goes to the HTTP server. It is not sourced from a URL query in this lesson.
- **Edge/origin 403:** both options are branches in one local server, not network destinations. An anonymous synthetic visitor is blocked at edge but permitted at an incorrectly protected origin; fixed denies both. This does not implement or bypass Cloudflare, discover origins, evade WAF rules, or solve browser challenges. [Cloudflare's 403 reference](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/4xx-client-error/error-403/) describes different causes of real 403 responses.

## Browser preview and evidence limits

The preview iframe and HTTP CSP both apply sandbox without allow-same-origin. Inline scripting is deliberately enabled inside this opaque-origin frame to demonstrate XSS; external resource loading, scripted connections, forms and nested frames are blocked by CSP. Alert is replaced with a training signal. The parent checks frame source and a fresh random token before accepting evidence. Fixed success also requires the same input rendered as literal text without image elements. It observes 650ms after rendering; absence of an alert signal during that interval is not proof against delayed or other execution paths.

This is browser sandboxing, not OS-level network isolation; frame self-navigation may behave differently from CSP-controlled subresource loading. Do not use it to run arbitrary untrusted programs, expose the application, or forward it through a tunnel. Use the educational local inputs.

## Verification

The default Python test suite requires no extra packages. Optional `tests/browser.cjs` uses Playwright on a desktop development environment and checks all seven manual challenges, live XSS execution, literal fixed output, parent DOM isolation, no DOM payload in HTTP requests, progress gating, and mobile overflow. With Playwright/Chromium installed and the local app running, use `node tests/browser.cjs`. Playwright is not needed to run the labs or Python tests on Termux.
