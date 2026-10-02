"""Tests for tests/openid-conformance-suite/baseline.py, the conformance baseline generator."""

import importlib.util
import json
from pathlib import Path

import pytest


BASELINE_PATH = Path(__file__).parent / "openid-conformance-suite" / "baseline.py"


@pytest.fixture(scope="module")
def baseline():
    spec = importlib.util.spec_from_file_location("openid_conformance_baseline", BASELINE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Shaped like a GitHub Actions job log of the suite's runner: an ISO timestamp,
# the runner's own timestamp, ANSI colours, and tab-indented condition lines.
CI = "2026-10-02T01:02:20.1234567Z 2026-10-02 01:02:20 "
RED = "\x1b[0m\x1b[01m\x1b[31m"
RESET = "\x1b[0m"
VERIFY = "Verify authorization endpoint response"
PLAN = "oidcc-hybrid-certification-test-plan"
LOG = "\n".join(
    [
        f"{CI}Running test module: oidcc-server[client_auth_type=client_secret_basic]",
        f"{CI}Script complete - results:",
        f"{CI}Results for [1] {PLAN} with configuration config/dot-oidcc-hybrid.json:",
        f"{CI}Test [1:1] oidcc-server[client_auth_type=client_secret_basic][response_type=code id_token]"
        f" AbC123 FINISHED - result {RED}FAILED{RESET}. 72 log entries - 28 SUCCESS 2 FAILURE, 1 WARNING",
        f"{CI}{RED}Unexpected failure: {RESET}",
        f"{CI}{RED}\tBlock name: '{VERIFY}' - Condition: 'RejectErrorInUrlQuery'{RESET}",
        f"{CI}{RED}\tBlock name: '{VERIFY}' - Condition: 'RejectErrorInUrlQuery'{RESET}",
        f"{CI}{RED}Unexpected warning: {RESET}",
        f"{CI}{RED}\tBlock name: 'Testing (the AS 'should' revoke)' - Condition: 'EnsureHttpStatus'{RESET}",
        f"{CI}Test [1:2] oidcc-server-rotate-keys[server_metadata=discovery] DeF456 FINISHED - result FAILED."
        " 40 log entries - 21 SUCCESS 1 FAILURE, 0 WARNING, 0.1 seconds",
        f"{CI}Expected failure: ",
        f"{CI}\tBlock name: '' - Condition: 'VerifyNewJwksHasNewSigningKey'",
        f"{CI}Test [1:3] oidcc-display-page[response_type=code token] GhI789 FINISHED - result PASSED.",
        f"{CI}Overall totals: ran 3 test modules. Conditions: 49 successes, 3 failures, 1 warnings.",
        f"{CI}\t\toidcc-server https://localhost.emobix.co.uk:8443/log-detail.html?log=AbC123",
        f"{CI}\t\t\tBlock name: '' - Condition: 'ShouldNotBeRecorded'",
    ]
)


def test_parse_log_records_unexpected_conditions(baseline):
    entries = baseline.parse_log(LOG)

    assert [(e["test-name"], e["condition"], e["expected-result"]) for e in entries] == [
        ("oidcc-server", "RejectErrorInUrlQuery", "failure"),
        ("oidcc-server", "EnsureHttpStatus", "warning"),
    ]
    failure = entries[0]
    assert failure["variant"] == {"client_auth_type": "client_secret_basic", "response_type": "code id_token"}
    assert failure["configuration-filename"] == "*dot-oidcc-hybrid.json"
    assert failure["current-block"] == VERIFY
    assert failure["baseline"] is True
    # A block name may itself contain quotes.
    assert entries[1]["current-block"] == "Testing (the AS 'should' revoke)"


def test_parse_log_skips_expected_conditions_and_the_trailing_summary(baseline):
    conditions = {entry["condition"] for entry in baseline.parse_log(LOG)}

    assert "VerifyNewJwksHasNewSigningKey" not in conditions
    assert "ShouldNotBeRecorded" not in conditions


def test_parse_log_reads_a_plain_runner_log(baseline):
    plain = "\n".join(
        [
            "2026-10-02 01:02:20 Results for [1] plan with configuration config/dot-oidcc.json:",
            "2026-10-02 01:02:20 Test [1:1] oidcc-max-age-1 Xyz INTERRUPTED - result FAILED. 4 log entries",
            "2026-10-02 01:02:20 Unexpected failure: ",
            "2026-10-02 01:02:20 \tBlock name: '' - Condition: 'WebRunner'",
        ]
    )

    [entry] = baseline.parse_log(plain)

    assert entry["test-name"] == "oidcc-max-age-1"
    assert entry["variant"] == {}
    assert entry["configuration-filename"] == "*dot-oidcc.json"


def test_merge_keeps_waivers_and_replaces_the_old_baseline(baseline):
    waiver = {
        "test-name": "oidcc-server-rotate-keys",
        "variant": "*",
        "configuration-filename": "*dot-oidcc-dcr.json",
        "current-block": "",
        "condition": "VerifyNewJwksHasNewSigningKey",
        "expected-result": "failure",
        "comment": "CI cannot rotate the key",
    }
    stale = {**waiver, "test-name": "oidcc-fixed-since", "variant": {}, "baseline": True}
    fresh = baseline.parse_log(LOG)

    merged = baseline.merge([waiver, stale], fresh)

    assert merged[0] == waiver
    assert stale not in merged
    assert merged[1:] == sorted(fresh, key=baseline._key)


def test_main_writes_and_removes_the_plan_file(baseline, tmp_path, monkeypatch):
    monkeypatch.setattr(baseline, "EXPECTED_DIR", tmp_path)
    monkeypatch.setattr(baseline, "HERE", tmp_path)
    log = tmp_path / "runner.log"
    log.write_text(LOG)

    assert baseline.main(["hybrid", str(log)]) == 0
    written = json.loads((tmp_path / "hybrid.failures.json").read_text())
    assert len(written) == 2

    # A plan with nothing left to record loses its file.
    log.write_text("2026-10-02 01:02:20 Results for [1] plan with configuration config/x.json:\n")
    assert baseline.main(["hybrid", str(log)]) == 0
    assert not (tmp_path / "hybrid.failures.json").exists()
