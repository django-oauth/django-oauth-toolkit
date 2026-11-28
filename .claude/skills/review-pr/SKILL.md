---
name: review-pr
description: Review a django-oauth-toolkit pull request and produce a findings report with severity, origin (introduced / pre-existing / out-of-scope) and context for each issue. Use when a maintainer asks for a review of a contributor's PR, a branch or a diff. Reports findings only; makes no blocking or approval calls.
---

# Review a PR

Produce a list of what is wrong, how bad, and where it came from. The maintainer decides what to ask of the contributor. Follow the "When reviewing" rules in `AGENTS.md`.

## Steps
1. Get the PR: description, linked issue, base ref, diff, existing review threads. Work out what the change sets out to do; that defines scope.
2. Check out the head locally so findings can be traced and reproduced.
3. Run one `reviewer` on the diff. Only for a change too large for one pass (a new grant type or endpoint, many files), run several `reviewer` agents in parallel, each given a distinct focus (for example one per endpoint, or spec conformance separately).
4. For each `pre-existing` or `out-of-scope` finding, search the repository's open issues and open pull requests (by symbol, endpoint, error text and RFC section; two or three phrasings) and record the matching number and title, or `untracked`.
5. Skip findings already raised in an existing thread on the PR.
6. Write the report below and give it to the maintainer.

## Report

```
## Review of #<n>: <title>

<One or two sentences: what the change does. No verdict.>

### Introduced by this change
| # | Severity | Finding | Location |
...
#### 1. <title>  ·  <severity>  ·  <confirmed | likely | uncertain>
<Context: what happens, what triggers it, why it matters, RFC section or project rule.>

### Pre-existing (not caused by this change)
... same shape, plus:
Evidence: <present on base at path:line>
Tracking: #<n> <title>  |  untracked

### Out of scope (beyond what this change sets out to do)
... same shape, plus Tracking.

### Untracked: candidates for new issues
- <finding title> (<severity>)
```

Order each section by severity. Keep an empty section with "None found" so it is clear it was checked.

## Rules
- No "blocking", "must fix", "nit", "optional", "LGTM" or approve / request-changes recommendation. Severity and origin are the only classifications.
- Describe problems; never include patches, suggestion blocks or rewritten code. The contributor does the work.
- Never present a `pre-existing` or `out-of-scope` finding as something the contributor got wrong. They go in their own sections, always.
- Carry the reviewer's confidence through: say when a finding is `likely` or `uncertain` and was not reproduced. Don't pad the report: a low-severity finding needs to be a real issue, not a preference.
- A suspected undisclosed vulnerability stays out of the PR and out of public issues. Tell the maintainer privately and point to `.github/SECURITY.md`.
- Do not post to the PR or open issues unless the maintainer asks. When asked to post, submit one review containing the report; when asked to open issues, use the `file-review-findings` skill.
