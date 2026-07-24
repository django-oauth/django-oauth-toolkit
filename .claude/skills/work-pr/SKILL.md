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
- Push the fix (no force-push; use a follow-up commit).
- **Reply on each review thread, then resolve it** — not a PR-level comment.
- Re-request Copilot review. Repeat until **CI green and Copilot has no comments**.

## Rules
- Reply on threads only; no PR-level status comments.
- End every GitHub post with the attribution footer.
- Never `git add -A` (it swept a `.venv` in once) — stage explicit paths.
- Don't poll with sleep; events + the fallback check-in wake you. Re-arm it silently if nothing changed.
- Don't self-merge. A subscription ends only when the PR is merged/closed.
