# Security Policy

Django OAuth Toolkit (DOT) takes reports about vulnerabilities in released
versions seriously. This policy explains which versions receive security fixes,
how to report a vulnerability privately, and what to expect from the maintainers.

## Supported versions

Security fixes target the latest published release line. The maintainers may
backport a fix to additional release lines when the severity, affected users, and
feasibility justify doing so. Each published advisory identifies the exact
affected and patched versions.

Users running an older release should first determine whether the issue is
present in the latest release. Upgrading to a supported release may be required
to receive a fix.

## Reporting a vulnerability

Use GitHub's
[private vulnerability reporting form](https://github.com/django-oauth/django-oauth-toolkit/security/advisories/new)
whenever possible. Do not open a public issue, discussion, pull request, or
publicly visible branch for an undisclosed vulnerability.

If GitHub private vulnerability reporting is unavailable, email
[django-oauth-security@googlegroups.com](mailto:django-oauth-security@googlegroups.com).
Do not send secrets, access tokens, personal data, or other production data.

Include as much of the following as possible:

- The affected DOT versions and deployment configuration.
- A description of the security boundary that can be bypassed.
- Reproduction steps or a minimal proof of concept using synthetic data.
- The expected and observed behavior.
- The potential confidentiality, integrity, or availability impact.
- Any preconditions, mitigations, or suspected affected OAuth/OIDC flows.
- Whether the report or a CVE request has already been sent elsewhere.
- Your preferred name and GitHub account for credit, or a request to remain
  anonymous.

Reports that are ordinary bugs, configuration questions, or hardening
suggestions without a security impact may be redirected to the public issue
tracker or discussions.

## Response and coordinated disclosure

The maintainers aim to acknowledge a report within three business days and
provide an initial assessment within ten business days. These are targets rather
than guarantees; complex reports may require additional investigation.

The reporter and maintainers should agree on a disclosure date that allows time
to validate the issue, develop and test a fix, and prepare releases. The
maintainers may adjust the schedule when there is active exploitation, an
accidental public disclosure, a release failure, or another material risk to
users.

The reporter is normally invited to the draft GitHub security advisory. A
temporary private fork is created when the reporter or another external
collaborator needs patch access; maintainer-owned remediation may proceed
directly in the shared private security repository. The trusted DOT maintainer
team may access the advisory and privately validate the patch. Once a candidate is promoted to the
public repository, the fix is considered disclosed even if publication of the
package or advisory is still in progress.

## CVEs and credit

DOT uses GitHub as its CVE Numbering Authority (CNA). The maintainers request a
CVE through the repository security advisory after confirming the vulnerability
and affected versions. If another CNA has already assigned a CVE, include that
identifier in the report so that duplicate assignments can be avoided.

Reporters and other contributors are credited in the advisory unless they
request anonymity. The project does not currently operate a bug bounty program.

## Maintainer process

The complete vulnerability response, private validation, release, and
publication workflow is documented in the public
[maintainer security process](../docs/security_process.rst). That document is
the operational source of truth for the project.
