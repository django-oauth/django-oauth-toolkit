---
name: work-pr
description: Open and drive a single-issue PR to merge-ready in django-oauth-toolkit. Use when implementing a bug/feature that ships as its own PR, or when babysitting an open PR through CI and Copilot review.
---

# Work a PR

One issue → one branch → one PR. Drive to green CI with no open review threads.

## Open
1. Branch off `master`: `claude/fix-<issue>-<slug>`.
2. Implement the smallest correct change. Add a regression test that **fails before, passes after**.
3. Add a `## [unreleased]` entry in `CHANGELOG.md` referencing `#<issue>` (skip for changes that aren't user-relevant, e.g. tooling).
4. Lint and run related tests locally: `ruff check` + `ruff format --check`, and `DJANGO_SETTINGS_MODULE=tests.settings python -m pytest <paths>`.
5. Commit, push `-u`. Open the PR filling `.github/pull_request_template.md`; `Fixes #<issue>`.
6. Request a Copilot review. Subscribe to PR activity. Arm a ~1h fallback check-in.

## On each CI / review event
- **Fix** if confident and small; **rebut** if the suggestion is wrong; **skip** duplicates/no-ops.
- Push the fix (prefer a follow-up commit; only force-push when you intentionally rebased, and always use `--force-with-lease`).
- **Reply on each review thread, then resolve it** — not a PR-level comment.
- Re-request Copilot review. Repeat until **CI green and Copilot has no comments**.

## When master advances
If the base moves while the PR is open — a merge-conflict or base-recovered notice, or CI that ran against a stale base — rebase onto the latest master and force-push with lease:

```
git fetch upstream
git rebase --autostash upstream/master
# resolve conflicts, re-run the affected tests
git push --force-with-lease
```

## Rules
- Reply on threads only; no PR-level status comments.
- Never `git add -A` (it swept a `.venv` in once) — stage explicit paths.
- Don't poll with sleep; events + the fallback check-in wake you. Re-arm it silently if nothing changed.
- Don't self-merge. A subscription ends only when the PR is merged/closed.
