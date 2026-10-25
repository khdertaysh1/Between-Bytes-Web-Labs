# v0.12.0 · Resource and identity labs

- Add four independent six-case rooms: uploads, path traversal, disclosure, recovery/sessions. Total: 13 rooms, 96 cases.
- Preserve the bilingual design and manual fields, HTTP editor, request replay/diff and encoding tools.
- Add virtual storage, path-resolution traces, deployment fixtures and identity ledgers with appropriate HTTP statuses and unchanged rejected state. No host file access, content execution or external transport.
- Extend the existing all-case HTTP and browser checks to all 96 cases; add resource, lifecycle, input-bound, capacity and no-IO contracts. Exact room/count assertions now cover 13/96; no checks are removed or skipped.

# v0.9.2 · Whole-project HTTP, state and browser audit

- Add explicit HTTP/body/state verification for all 50 academy cases and all 13 foundation rooms, malformed-input coverage and browser edge regressions.
- Correct wrong-password 401 and SQL syntax-error 400 responses; isolate export/download reference types, return 404 for missing resources and correct Alice CSV data.
- Validate required fields for every case, Unicode strings, JSON duplicate fields/non-finite constants, known methods and bounded account identities.
- Fix malformed XSS URL previews and non-ASCII webhook/CSRF token handling; surface preview JavaScript errors without false completion marks.
- Lock request controls while work is pending, cancel stale previews on variant changes and identify the responding variant. Do not invent an HTTP protocol version in response displays.
- Correct redirect external-target classification and include per-attempt rate-limit outcomes.
- Publish docs/audit-0.9.2.md with the verified matrix and explicit local-model/browser limitations.

# v0.9.1 · Correct and explain payment HTTP outcomes

- Reject mismatched fixed quote inputs with 422 before changing order state, rather than silently normalizing and returning 200. Reject sub-cent mismatches and missing required payment fields.
- Return 409 for fully rejected coupon/gift batches and 207 with per-operation outcomes for partial batches. Retain safe 200 acknowledgements for idempotent valid event replays.
- Label payment POST and resource GET results separately and explain accepted, rejected, partial and ignored-duplicate outcomes in both languages.
- Cover actual HTTP statuses and unchanged resources for all 16 payment cases, plus partial batches, missing inputs and fractional amounts.

# v0.9 · Grouped application labs and persisted business workflows

- Replace the 50-card landing page with five labs and internal case navigation, keeping all 50 cases open. Make the academy the default home and retain the original rooms at `/foundations`.
- Rewrite all 50 cases with application-specific narratives, source-to-sink explanations, evidence interpretation and vulnerable/fixed code excerpts in Arabic and English.
- Persist checkout quotes, order revisions, provider receipts, fulfilment, refunds, coupon redemptions, gift credit and subscription records. Add independent GET readback and ETags.
- Verify local canonical provider events with HMAC-SHA256 and keep accepted event processing idempotent. Preserve prior legitimate settlement when rejecting a later invalid request.
- Add JSON application routes with actual HTTP errors, request IDs and rate-limit headers; separate classroom assessment metadata from business response bodies.
- Keep the local provider, deterministic stale-read schedule, closed transport fixtures and opaque-origin XSS limits explicit.

# v0.8 · Advanced scenario academy

- Add 50 bilingual, open scenarios across payment logic (16), authorization (10), rate limits (7), XSS contexts (12) and other code flaws (5), alongside the 13 foundation rooms.
- Add `/academy` tracks, search, difficulty ordering, editable JSON requests, synthetic application results, progressive hints, notes, evidence exports and local completion marks.
- Bind non-browser evidence to matching request fingerprints and a working fixed control; keep browser-assisted XSS observations distinct from server flags.
- Add real in-memory SQLite parsing and sandboxed browser rendering across 12 XSS contexts (11 execution checks plus href-policy inspection), with 36 payload/control samples, including actual fragment/search sources and separately retrieved stored comments.
- Keep payments/providers, source rotation, stale-read scheduling and non-SQL services as clearly labeled bounded fixtures without external targets.
- Add full Arabic/English case guides and Termux update instructions.

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
