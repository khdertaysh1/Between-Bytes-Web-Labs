# Open learning path — 0.6

All 13 lessons and exercises are available immediately, in any order. The six levels are topic groups only. Points, prerequisite checks and score-based access have been removed.

Each lesson keeps its expanded explanation, hinted practice, fix/limitations and independent practical exercise. Start an exercise from the third tab without completing any other lesson. Assessment variants still use different synthetic accounts, invoice IDs or BB-EXAM markers where appropriate. Evidence checklists verify actual classroom behavior, not scores.

Optional local completion marks survive refresh. Previous successful assessments migrate to marks only; they do not grant or restrict access. Clearing completion never locks lessons. Exported evidence contains the lesson, round type, synthetic inputs and observations, without point fields. This is not a certification or tamper-resistant examination service.

Starting a round resets the shared synthetic server state. Avoid concurrent rounds in multiple tabs. Browser and fixture limitations remain documented in [advanced exercises](advanced.en.md).

Developer checks: Python unittest suite, `node tests/progression.test.cjs`, and optional Playwright `node tests/browser.cjs` with a local server. Coverage includes direct access to all lessons from fresh/reset state, legacy completion migration, exercises, persistence, browser isolation and mobile layouts.
