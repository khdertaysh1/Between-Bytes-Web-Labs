# Repository contribution rules

## Branch and review policy

- Read the latest main branch, these instructions and CONTRIBUTING.md before editing.
- Make changes in a separate branch and open a pull request. Never push directly to main/master or force-push over another contributor's changes.
- Do not merge a PR, enable auto-merge, weaken branch protection or bypass checks. The user reviews the concrete PR and decides whether to merge it. Passing tests alone is not approval.
- Keep scheduled updates separate from the user's ordinary changes, and preserve current work.

## Required verification

- Run `python tools/quality.py python` and `python tools/quality.py sensitivity`.
- For changes affecting behavior, UI, sessions or previews, install the locked dev dependencies (`npm ci`) and Chromium (`npx --no-install playwright install chromium`), then run `python tools/quality.py browser`.
- CI runs all Python and browser groups; the required status is `quality-gate`. Do not report a group as passed if it was not run or if it was skipped/cancelled.
- Do not delete tests, reduce assertions, lower the discovery minimum, skip a suite, or change CI just to make a failing implementation pass. Explain any legitimate test/infrastructure update explicitly in the PR for review.
- Guard valid use as well as denied operations. Rejected writes must preserve state. A 200 status is not automatically a vulnerability or a successful business operation.
- The sensitivity checks intentionally break protections in disposable copies. Never apply their mutants to the actual source. If a refactor changes a mutation anchor, update the guard with reviewable evidence, not a skip.

## Product constraints

- Preserve the current design, clear Arabic/English explanations, mobile layout and simple Termux operation. All cases remain open without points or locks.
- The app itself needs only Python 3.10+. Node/Playwright are development-only dependencies.
- Keep synthetic accounts/payment data, loopback-only default services, sandboxed previews and bounded resources. Do not test third-party sites.
- Label policy models and browser evidence accurately. The two browser-practice ports are cross-origin but same-site; do not claim SameSite bypass. SSRF/redirect models do not perform external transport/navigation.
- Summarize the change, test evidence, unrun checks and material limits in the PR. Keep unrelated refactors out.
