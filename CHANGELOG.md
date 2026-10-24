# Changelog

## 0.7.0 — 2026-10-24

- Full Arabic/English interface and authored learning content for all 13 rooms, with persisted language and RTL/LTR layouts.
- Application-themed workspaces across every room and a restricted local HTTP replay workbench.
- Bounded per-browser classroom state, server-observed journals and per-round synthetic flags for server-observable criteria.
- Explicit browser-assisted verification boundaries for XSS/CORS; modeled SSRF/redirect/file scope preserved.
- All rooms remain open without points or prerequisite locks.
- 33 Python tests plus both-language browser workflow and localization/workbench/session checks.


## 0.6.0 — 2026-10-24

- Removed points and all prerequisite locks. All 13 lessons and exercises are open immediately in any order.
- Kept explanations, practice, independent exercises and optional local completion marks.
- Migrated prior achievements to completion marks; reset never restricts access.
- Browser checks cover direct access to every lesson from a fresh state and after clearing completion.


## 0.5.0 — 2026-10-24

- Six new explained lessons with practice and scored assessments: CSRF, CORS, open redirect, SSRF, API keys and exposed ENV/backup files.
- Real two-origin loopback browser exercises for credentialed CORS reads and synthetic-session CSRF writes; automatic second-origin lifecycle.
- Explicit no-network SSRF transport model, redirect decision preview and in-memory file/secret fixtures.
- Six levels, 13 assessments and 1300 maximum points; prior scores preserved.
- 28 passing Python tests, progression checks and browser coverage of all 13 assessments, including real cross-origin behavior and loopback-only requests.


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
