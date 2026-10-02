#!/usr/bin/env python3
"""Record a plan's current failures and warnings as its conformance baseline.

The suite's runner fails a plan for any failure or warning not listed in
``expected/<plan>.failures.json`` and for any listed one that did not happen.
Listing every known toolkit gap therefore turns a plan into a ratchet: a new
failure (a regression) fails CI, and so does a fixed one until its entry is
removed, which keeps the file an exact record of where the plan stands.

This script rewrites the baseline part of that file from a runner log, such
as ``reports/runner.log`` from a CI artifact or the job log itself. Entries it
writes carry ``"baseline": true``; hand-written entries (waivers with their
own reason, such as conditions CI cannot exercise) are kept as they are and
take precedence. Run it after a change that moves a plan, review the diff,
and commit it with the change::

    python tests/openid-conformance-suite/baseline.py basic reports/runner.log

Only conditions reported as *unexpected* are recorded, so already-waived
conditions are not duplicated. A module that did not run to completion cannot
be baselined; the runner fails the plan for it regardless.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
EXPECTED_DIR = HERE / "expected"

BASELINE_COMMENT = (
    "Baseline: a known toolkit conformance gap, recorded so that a regression fails CI. "
    "Delete this entry (or regenerate with baseline.py) in the change that fixes it."
)

ANSI = re.compile(r"\x1b\[[0-9;]*m")
# A GitHub Actions job log prefixes each line with an ISO timestamp; the runner
# prefixes its own lines with "YYYY-MM-DD HH:MM:SS ".
PREFIXES = (
    re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z "),
    re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d "),
)
PLAN_HEADER = re.compile(r"^Results for \[\d+\] \S+ with configuration (?P<config>\S+?):?$")
MODULE = re.compile(
    r"^Test \[\d+:\d+\] (?P<name>[^\s\[]+)(?P<variants>(?:\[[^\]]*\])*) \S+ \S+ - result \S+\."
)
VARIANT = re.compile(r"\[(?P<key>[^=\]]+)=(?P<value>[^\]]*)\]")
CONDITION = re.compile(r"^\s*Block name: '(?P<block>.*)' - Condition: '(?P<condition>[^']*)'$")
SECTIONS = {
    "Unexpected failure:": "failure",
    "Unexpected warning:": "warning",
}


def _content(line: str) -> str:
    line = ANSI.sub("", line.rstrip("\n"))
    for prefix in PREFIXES:
        line = prefix.sub("", line, count=1)
    return line


def parse_log(text: str) -> list[dict]:
    """Return one entry per unexpected (module, variant, block, condition, result)."""
    entries: list[dict] = []
    seen: set[tuple] = set()
    config = None
    module = None
    variant: dict[str, str] = {}
    section = None
    for raw in text.splitlines():
        line = _content(raw)
        stripped = line.strip()
        if match := PLAN_HEADER.match(stripped):
            config = "*" + Path(match["config"]).name
            module, section = None, None
            continue
        if stripped.startswith("Overall totals:"):
            # The per-module results end here; any later summary repeats them.
            module, section = None, None
            config = None
            continue
        if config is None:
            continue
        if match := MODULE.match(stripped):
            module = match["name"]
            variant = {m["key"]: m["value"] for m in VARIANT.finditer(match["variants"])}
            section = None
            continue
        if stripped in SECTIONS:
            section = SECTIONS[stripped]
            continue
        if stripped.endswith(":") and not stripped.startswith("Block name"):
            # "Expected failure:", "Expected warning:" and the like.
            section = None
            continue
        if module and section and (match := CONDITION.match(line)):
            key = (module, json.dumps(variant, sort_keys=True), config, match["block"], match["condition"])
            if key in seen:
                continue
            seen.add(key)
            entries.append(
                {
                    "test-name": module,
                    "variant": dict(sorted(variant.items())),
                    "configuration-filename": config,
                    "current-block": match["block"],
                    "condition": match["condition"],
                    "expected-result": section,
                    "comment": BASELINE_COMMENT,
                    "baseline": True,
                }
            )
    return entries


def _key(entry: dict) -> tuple:
    return (
        entry["test-name"],
        json.dumps(entry.get("variant"), sort_keys=True),
        entry["configuration-filename"],
        entry["current-block"],
        entry["condition"],
    )


def merge(existing: list[dict], baseline: list[dict]) -> list[dict]:
    """Keep hand-written entries first, then the new baseline, without duplicate keys."""
    kept = [entry for entry in existing if not entry.get("baseline")]
    taken = {_key(entry) for entry in kept}
    fresh = sorted((entry for entry in baseline if _key(entry) not in taken), key=_key)
    return kept + fresh


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("plan", help="plan name, as in run.py --list-plans")
    parser.add_argument("log", type=Path, help="runner output for that plan (runner.log or a CI job log)")
    args = parser.parse_args(argv)

    baseline = parse_log(args.log.read_text(errors="replace"))
    path = EXPECTED_DIR / f"{args.plan}.failures.json"
    existing = json.loads(path.read_text()) if path.exists() else []
    entries = merge(existing, baseline)
    if entries:
        path.write_text(json.dumps(entries, indent=4) + "\n")
    elif path.exists():
        path.unlink()
    kept = sum(1 for entry in entries if not entry.get("baseline"))
    print(f"{path.relative_to(HERE)}: {len(entries) - kept} baseline entries, {kept} hand-written kept")
    return 0


if __name__ == "__main__":
    sys.exit(main())
