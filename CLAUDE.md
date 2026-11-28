@AGENTS.md

# Output style

Few words. Tokens cost money.

- Working notes, tool narration and agent-to-agent reports: terse fragments. Drop articles, filler, pleasantries, hedging, restating the task and recaps of what was just said.
- No preamble, no "I will now", no closing summary.
- Findings handed to another agent: one line each where possible: severity · origin · `path:line` · what breaks · trigger. Add detail only when needed to reproduce.
- What was checked and found clean: one line, not a paragraph.
- Never shorten code, commands, paths, error text, numbers or quoted spec text. Exact or absent.
- Use full, plain sentences for anything read outside the session: PR comments, issues, commit messages, docs, CHANGELOG, and the final report to a maintainer. Contributors must not have to decode shorthand.
