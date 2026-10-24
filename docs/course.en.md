# Course progression and practical assessments

Each lesson now contains an expanded explanation, hinted manual practice, root cause/fix, and a separate practical assessment. Begin an assessment from the third lesson tab. It resets the server round, disables hints and automatic demos, and awards points from evidence criteria rather than multiple-choice answers or viewing a demonstration.

Level 1: enumeration, rate limiting, reset-mail abuse. Level 2: IDOR and the local edge/origin authorization model; requires all three level-one exams (300 points). Level 3: reflected and DOM XSS; requires all five preceding exams (500 points). Each passed exam awards 100 points exactly once, maximum 1300. Practice does not award points. Replays do not increase totals; incomplete rounds do not deduct points.

Assessment variants use Bob's synthetic account, visitor@example.test as an absent account, IDOR invoices 2001/2002 for Alice/Bob, and the BB-EXAM alert marker for XSS. The browser must observe the required execution signal in vulnerable mode and literal rendering of the same input in fixed mode. Lack of execution within the 650ms observation window is not proof against delayed or other payload paths. The 403 exercise remains a local branch simulation, not a Cloudflare bypass.

Progress uses localStorage, persists on refresh, and is local to the browser. Version 0.3 progress is migrated as practice only, without awarding exam points. Clearing progress confirms before resetting scores and locking later levels. Direct navigation to locked lessons returns to the roadmap. This is deliberately an educational, inspectable client-side mechanism, not a tamper-resistant examination, certificate system or authenticated leaderboard. Server state is shared by tabs connected to one process; concurrent rounds can interfere.

Run Python tests as before and `node tests/progression.test.cjs` for pure scoring/prerequisite checks. Optional `tests/browser.cjs` requires Playwright/Chromium and a running local server; it exercises all exams, practice/assessment separation, one-time scores, prerequisites, refresh persistence, XSS isolation and mobile overflow. Neither Node nor Playwright is needed for normal Termux use.

Version 0.5 adds level 4 (CSRF/CORS, 700 prerequisite points), level 5 (modeled redirect/SSRF, 900), and level 6 (API keys/exposed file fixtures, 1100). All prior exams are required; v0.4 scores remain intact. See [advanced lesson scope](advanced.en.md).
