# Contributing safely

Work on a branch and open a pull request. Do not push directly to `main`, merge automatically, or treat green tests as permission to merge. The owner reviews the PR and chooses whether to merge. This applies to scheduled and AI-assisted updates regardless of model.

The application still runs with Python 3.10+ alone. Node and Playwright are needed only for development/CI browser checks. Preserve the current design, Arabic/English explanations and mobile/Termux operation.

## Run the checks

```bash
python tools/quality.py python
python tools/quality.py sensitivity
npm ci --ignore-scripts --no-audit --no-fund
npx --no-install playwright install chromium
python tools/quality.py browser
```

On Linux CI, Playwright installs required system packages with `npx --no-install playwright install --with-deps chromium`. For an existing local Chromium, set `BB_BROWSER_PATH` to its executable. The browser runner starts and stops its own loopback server on port 8000; stop any manually running lab on that port first.

Browser groups can be run separately with `--group academy`, `--group workspace` or `--group regressions`. CI runs all three. Logs and supported screenshots are written under `artifacts/`, ignored by Git. CI artifacts are retained for 14 days. A timeout, missing suite, unexpectedly small Python discovery, skipped/expected-failure Python tests, skipped/cancelled dependency, or failed assertion must fail the gate.

Sensitivity checks run existing passing tests in disposable copies, deliberately break payment/ownership/CSRF checks there, and require assertion failures. They never modify the real application. A changed mutation anchor needs a reviewed guard update; do not skip it. These three checks are evidence that key tests detect regressions, not exhaustive mutation coverage.

## Owner activation: main branch protection

Adding a workflow does not itself block direct pushes or failed merges. The connected GitHub integration cannot administer branch protection. The owner must activate protection and merge this initial CI PR after review.

1. Let this PR run successfully and verify the `quality-gate` check.
2. Open Settings → Branches → Add classic branch protection rule, with branch pattern `main`.
3. Enable **Require a pull request before merging**, **Require status checks to pass before merging**, and **Require branches to be up to date before merging**. Select the exact check **quality-gate** (GitHub Actions).
4. Enable **Require conversation resolution before merging** and **Do not allow bypassing the above settings** / include administrators. Keep force pushes and deletion disabled. Do not add an automation bypass actor.
5. Review and merge the initial CI PR manually. Subsequent PRs must pass the gate. Keep automation prompts PR-only; do not enable auto-merge.

A complete REST request body is provided in `.github/branch-protection.json`. An owner with GitHub CLI authenticated with administration rights can apply it with:

```bash
gh api --method PUT repos/khdertaysh1/Between-Bytes-Web-Labs/branches/main/protection --input .github/branch-protection.json
```

This configuration requires PRs/checks but sets formal required approvals to **0** to avoid locking a single owner out of owner-authored PRs: GitHub does not let an author approve their own PR. Manual owner review/merge is the operating policy. If a separate trusted reviewer is available, require **1** approval and optionally Code Owner review; `.github/CODEOWNERS` declares ownership but does not enforce review by itself.

Review changes to tests, workflows, runners, dependency pins and this policy especially carefully. A model using the owner's credentials can edit these files; tests and prompts are not an immutable security boundary. Required checks must be enabled on GitHub, and a separate reviewer/identity provides stronger independent review. Account access and future scheduled-task availability are separate from these repository safeguards.

Official references: [protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches), [required reviews](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/reviewing-changes-in-pull-requests/approving-a-pull-request-with-required-reviews), [Playwright CI](https://playwright.dev/docs/ci).
