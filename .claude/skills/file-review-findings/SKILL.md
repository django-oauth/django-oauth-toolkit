---
name: file-review-findings
description: Open GitHub issues for pre-existing or out-of-scope findings from a django-oauth-toolkit PR review, after checking that no issue or PR already covers them. Use when a maintainer asks to file, track or open issues for review findings.
---

# File review findings as issues

Findings that a PR did not cause are tracked as issues, so the contributor is not asked to fix them and they are not lost.

## Steps
1. Take the `pre-existing` and `out-of-scope` findings the maintainer named (default: those the review marked `untracked`).
2. Search again for each, open issues and open PRs, by symbol, endpoint, error text and RFC section. If one covers it, do not open a duplicate: report the match, and add a comment there only if the finding adds new information (a reproduction, an affected path, an RFC citation).
3. Set aside anything that looks like an undisclosed vulnerability. It goes through private vulnerability reporting per `.github/SECURITY.md`, never a public issue. Tell the maintainer.
4. Show the maintainer the list of issues you are about to open (title and one line each) and open them once they confirm.
5. Open one issue per finding using the matching template in `.github/ISSUE_TEMPLATE/` (`bug_report.md` for defects, `feature_request.md` for gaps):
   - Title: the defect, not the PR ("Refresh token reuse is not detected when ..." rather than "Found in #1234").
   - Body: what happens, how to trigger it, expected behavior with the RFC section, `path:line` on the default branch, severity. Self-contained: readable without the PR.
   - End with "Found while reviewing #<pr>; present before that change." so it is clear the PR's author did not cause it.
6. Report the issue numbers, and which findings matched existing issues or PRs.

## Rules
- One issue per finding; don't bundle unrelated defects.
- Describe the problem; don't prescribe an implementation.
- Don't comment on the contributor's PR about these unless the maintainer asks. If asked, one line: "Unrelated to this change, tracked in #<n>."
