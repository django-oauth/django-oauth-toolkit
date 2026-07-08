"""
Compliance-matrix reporting plugin.

Every test may declare one or more ``@pytest.mark.compliance(spec, section,
requirement)`` markers binding it to a specification requirement. This plugin
collects those bindings together with each test's outcome and, at the end of the
session, writes a compliance matrix (Markdown + JSON) mapping

    specification -> section -> requirement -> test -> status

It also records the requirements that are explicitly *not supported* by
django-oauth-toolkit, so the report is honest about the library's boundaries.

The plugin lives with the e2e suite, so it only activates when these tests run.
"""

import json
import os
from collections import defaultdict
from datetime import datetime, timezone


# Requirements that django-oauth-toolkit does not implement. Listed so the
# compliance report distinguishes "not supported" from "untested".
NOT_SUPPORTED = [
    ("RFC 9126", "Pushed Authorization Requests (PAR)", "No PAR endpoint."),
    ("RFC 9101", "JWT-Secured Authorization Request (JAR)", "No request/request_uri object support."),
    ("RFC 9449", "DPoP", "No DPoP-bound tokens."),
    ("RFC 8705", "mTLS client authentication", "No tls_client_auth / self_signed_tls_client_auth."),
    ("OIDC Core 1.0", "private_key_jwt / client_secret_jwt", "Only client_secret_basic/_post."),
    ("OAuth 2.0 Form Post Response Mode", "response_mode=form_post", "Only query/fragment."),
    ("OIDC Session Management / Logout", "Back-/Front-Channel Logout", "Only RP-Initiated Logout."),
    ("OIDC Core 1.0", "pairwise subject type", "Only public subject type."),
]

_STATUS_RANK = {"error": 3, "failed": 2, "skipped": 1, "passed": 0}


def _worst(a, b):
    return a if _STATUS_RANK[a] >= _STATUS_RANK[b] else b


def _section_sort_key(section):
    """Sort dotted spec sections numerically (3.1.2 before 3.10) when possible."""
    parts = section.split(".")
    if all(p.isdigit() for p in parts):
        return (0, [int(p) for p in parts])
    return (1, section)


class CompliancePlugin:
    def __init__(self, config):
        self.config = config
        # nodeid -> {"requirements": [(spec, section, req)], "spec_family": str}
        self.registry = {}
        # nodeid -> status string
        self.outcomes = {}

    # Build the requirement registry once collection is done.
    def register(self, items, spec_by_package):
        for item in items:
            reqs = []
            for marker in item.iter_markers("compliance"):
                if len(marker.args) >= 3:
                    reqs.append((marker.args[0], str(marker.args[1]), marker.args[2]))
            family = None
            for part in item.nodeid.replace("\\", "/").split("/"):
                if part in spec_by_package:
                    family = spec_by_package[part][0]
                    break
            if reqs:
                self.registry[item.nodeid] = {"requirements": reqs, "spec_family": family}

    def pytest_runtest_logreport(self, report):
        if report.nodeid not in self.registry:
            return
        if report.when == "setup" and report.failed:
            status = "error"
        elif report.when == "setup" and report.skipped:
            status = "skipped"
        elif report.when == "call":
            status = "failed" if report.failed else ("skipped" if report.skipped else "passed")
        else:
            return
        prev = self.outcomes.get(report.nodeid, "passed")
        self.outcomes[report.nodeid] = _worst(prev, status)

    # spec -> section -> list of {requirement, test, status}
    def _build_matrix(self):
        matrix = defaultdict(lambda: defaultdict(list))
        for nodeid, info in self.registry.items():
            status = self.outcomes.get(nodeid, "not-run")
            test_name = nodeid.split("::")[-1]
            for spec, section, requirement in info["requirements"]:
                matrix[spec][section].append(
                    {"requirement": requirement, "test": test_name, "nodeid": nodeid, "status": status}
                )
        return matrix

    def _summary(self, matrix):
        counts = defaultdict(int)
        for sections in matrix.values():
            for rows in sections.values():
                for row in rows:
                    counts[row["status"]] += 1
        return dict(counts)

    def write_reports(self):
        if not self.registry:
            return None
        out_dir = os.environ.get("COMPLIANCE_MATRIX_DIR", os.getcwd())
        os.makedirs(out_dir, exist_ok=True)
        matrix = self._build_matrix()
        summary = self._summary(matrix)
        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

        json_path = os.path.join(out_dir, "compliance-matrix.json")
        with open(json_path, "w") as fh:
            json.dump(
                {
                    "generated": generated,
                    "summary": summary,
                    "specifications": {
                        spec: {section: rows for section, rows in sections.items()}
                        for spec, sections in matrix.items()
                    },
                    "not_supported": [{"spec": s, "feature": f, "note": n} for s, f, n in NOT_SUPPORTED],
                },
                fh,
                indent=2,
                sort_keys=True,
            )

        md_path = os.path.join(out_dir, "compliance-matrix.md")
        icon = {"passed": "✅", "failed": "❌", "error": "❌", "skipped": "⚠️", "not-run": "—"}
        with open(md_path, "w") as fh:
            fh.write("# OAuth 2.0 / OpenID Connect Compliance Matrix\n\n")
            fh.write(f"_Generated {generated} from the end-to-end suite (`tests/e2e`)._\n\n")
            total = sum(summary.values())
            passed = summary.get("passed", 0)
            fh.write(f"**{passed}/{total} requirement checks passing.** ")
            fh.write(" · ".join(f"{icon.get(k, k)} {k}: {v}" for k, v in sorted(summary.items())) + "\n\n")
            for spec in sorted(matrix):
                fh.write(f"## {spec}\n\n")
                fh.write("| Section | Requirement | Test | Status |\n")
                fh.write("|---|---|---|---|\n")
                for section in sorted(matrix[spec], key=_section_sort_key):
                    for row in matrix[spec][section]:
                        fh.write(
                            f"| {section} | {row['requirement']} | `{row['test']}` | "
                            f"{icon.get(row['status'], row['status'])} {row['status']} |\n"
                        )
                fh.write("\n")
            fh.write("## Not supported by django-oauth-toolkit\n\n")
            fh.write("These specification features have no implementation and are out of scope.\n\n")
            fh.write("| Specification | Feature | Note |\n|---|---|---|\n")
            for spec, feature, note in NOT_SUPPORTED:
                fh.write(f"| {spec} | {feature} | {note} |\n")
        return md_path, json_path
