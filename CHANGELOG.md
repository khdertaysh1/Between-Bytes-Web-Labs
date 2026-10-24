# Changelog

## 0.4.0 — 2026-10-24

- Expanded Arabic in-page explanations for all seven lessons: concepts, request flow, evidence, impact, fixes and limitations.
- Three prerequisite-based levels with a roadmap and 100 one-time points per passed practical assessment, maximum 700.
- Separate hinted practice and hint-free assessments with variant synthetic inputs and BB-EXAM execution markers.
- Local score persistence, explicit reset and practice-only migration of v0.3 completion.
- Progression rules and end-to-end assessment tests; no server-authenticated or tamper-resistant grading claims.


## 0.3.0 — 2026-10-23

- Four new lessons: server-side IDOR, reflected XSS, DOM XSS, and synthetic edge/origin authorization.
- Hands-on workbenches for all seven lessons with editable inputs, evidence checklists, progressive hints and JSON downloads.
- Progress requires manual challenge evidence; automatic demonstrations do not complete challenges.
- Opaque-origin sandboxed XSS previews, HTML text-context fix, and DOM textContent fix.
- 19 passing Python tests and passing Chromium checks for all seven manual challenges, XSS execution/isolation, progress gating and mobile layouts.


## 0.2.0 — 2026-10-23

- Redesigned Arabic learning dashboard and responsive lesson pages.
- Three-stage lessons: scenario, live comparison, root cause and fix.
- Bounded real HTTP comparisons with evidence, interpreted results and expected-outcome checks.
- Manual request controls, local progress tracking and comprehension questions.


## 0.1.0 — 2026-10-23

- Three paired vulnerable/fixed lessons: account enumeration, spoofed-identity rate limiting, and reset-email abuse.
- Arabic mobile-friendly interface and Arabic/English lesson guides.
- Loopback-only HTTP server with no external dependencies or mail delivery.
- Twelve behavioral and local HTTP integration tests; verified on Python 3.12.
- MIT license for reuse with attribution.
