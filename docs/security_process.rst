.. _security-process:

Security Vulnerability Response and Release Process
===================================================

This document is the operational source of truth for Django OAuth Toolkit (DOT)
security work. It describes how maintainers receive reports, coordinate with
researchers, validate fixes in private, publish releases through the primary
repository, and disclose advisories.

The reporter-facing commitments are defined in the
`repository security policy
<https://github.com/django-oauth/django-oauth-toolkit/security/policy>`_.
OAuth and OpenID Connect implementation guidance is documented separately in
:doc:`security`.

Principles
==========

* Protect vulnerability details until the coordinated disclosure begins.
* Treat the DOT maintainer team as the shared security trust boundary.
* Limit an external reporter to the advisory and temporary fork for their
  report unless the maintainers deliberately grant broader access.
* Keep policy and operational procedure public. Embargoed case data, patches,
  proofs of concept, and CI output remain private until disclosure.
* Use clear commit messages and preserve useful history. Confidentiality before
  disclosure must not depend on vague messages or hidden intent.
* Validate every fix against applicable OAuth/OIDC specifications, supported
  Python and Django versions, database backends, and deployment topologies.
* Build and publish PyPI packages only from the primary public repository.
* Treat the first promotion of a patch to a public branch as the end of its
  embargo.
* Communicate and fix forward if the public cutover fails.

Roles and access
================

Reporter
--------

The reporter provides reproduction information, helps validate impact, reviews
the proposed remediation when possible, and agrees on a coordinated disclosure
schedule. GitHub private vulnerability reporting normally adds the reporter to
the draft advisory automatically.

Maintainer team
---------------

The maintainer team is trusted to access all DOT security work. Maintainers may
triage reports, collaborate on advisories, review patches, run private
validation, prepare releases, and publish advisories. At least one maintainer
other than the patch author should review a security fix whenever availability
allows.

Security release coordinator
----------------------------

One maintainer coordinates a given security release. The coordinator tracks the
affected versions, CVE requests, included patches, CI results, release version,
disclosure timing, PyPI publication, and advisory publication.

Repositories and data boundaries
================================

Primary public repository
-------------------------

``django-oauth/django-oauth-toolkit`` is the authoritative source repository.
Its CI performs the final public validation, and its release workflow builds and
publishes the PyPI artifacts.

Draft advisory and temporary fork
---------------------------------

Each vulnerability is tracked in a repository security advisory. Its temporary
private fork provides the workspace shared with the reporter. GitHub prevents
integrations, including CI, from accessing these temporary forks, so the fork
is not the project's full validation environment. Creating a temporary fork is
optional: use it when the reporter or another external collaborator needs patch
access. When a maintainer owns the remediation, development can proceed directly
in the shared security repository while the advisory remains the authoritative
case record.

Shared private security repository
----------------------------------

``django-oauth-toolkit-security`` is an independent private mirror used by the
trusted maintainer team. It provides private pull requests, agents, Actions, and
full-stack validation before public promotion. It is not the CNA record and
does not replace the repository security advisory.

The security repository must:

* Grant access only to the trusted maintainer team and approved automation.
* Keep its default branch synchronized with the primary public repository.
* Contain no PyPI publishing credentials or production deployment credentials.
* Disable package publication and GitHub release creation.
* Avoid sending private coverage, logs, artifacts, or source to unapproved
  third-party services. Codecov uploads must be disabled there.
* Give the GitHub Actions token read-only permissions unless a reviewed job has
  a documented need for more.
* Avoid ``pull_request_target`` for patch validation.
* Require review of changes to workflows, Actions, dependencies, or build
  configuration before executing reporter-supplied code.
* Use short retention for private Actions logs, caches, and artifacts.

Only incident-specific information is private. This public document remains the
canonical procedure.

Report intake and triage
========================

#. Acknowledge the report using the targets in the security policy.
#. Confirm that discussion is private. If details were posted publicly, capture
   the location and treat the report as potentially disclosed.
#. Reproduce the behavior using synthetic data and a supported DOT version.
#. Determine the violated security boundary, affected OAuth/OIDC flows,
   prerequisites, and realistic impact.
#. Identify affected released versions and deployment configurations.
#. Assign an initial severity using a CVSS vector and identify applicable CWEs.
#. Decide whether the report is a vulnerability, an ordinary defect, expected
   behavior, a configuration error, or a hardening opportunity.
#. Agree with the reporter on communication cadence and a target disclosure
   date. Record any disclosure deadline supplied by the reporter.
#. Assign a security release coordinator.

Do not copy proofs of concept, reporter identity, credentials, or unpublished
impact details into public issues, projects, branches, or workflow inputs.

Advisory and CVE management
===========================

The repository security advisory is the authoritative case record and GitHub
CNA interface.

#. Convert a privately reported vulnerability to a draft advisory, or create a
   draft advisory when a maintainer discovers the issue.
#. Add the DOT maintainer team as advisory collaborators.
#. Keep the reporter as a collaborator unless access must be removed for a
   documented reason.
#. Record the ``pip`` ecosystem, ``django-oauth-toolkit`` package, affected
   version ranges, planned patched versions, CVSS vector, CWEs, impact,
   mitigations, and credits.
#. Search for an existing CVE assignment before requesting one.
#. Request a CVE through GitHub after the vulnerability and affected versions
   are sufficiently established. Do not request the same CVE from another CNA.
#. Keep the advisory in draft until coordinated publication.

Every advisory must eventually state the exact vulnerable version ranges and
first patched version. Multiple advisories may name the same patched release.

Patch development paths
=======================

Choose the shortest path that provides the collaboration the remediation needs.
The temporary fork is not a required intermediate step when a maintainer will
implement and validate the fix.

Common remediation requirements
-------------------------------

Regardless of the development path:

* Base the patch on a known commit from the applicable public release branch.
* Develop the smallest remediation that closes the security boundary without
  unrelated refactoring.
* Add regression tests that demonstrate the vulnerable behavior and verify the
  remediation.
* Review the change against the relevant OAuth, OIDC, Django, and OAuthLib
  behavior.
* Invite the reporter to verify the remediation when practical.
* Use clear Conventional Commit messages. Reference the GHSA and reserved CVE
  when doing so does not conflict with the agreed workflow.

Direct maintainer path
----------------------

Use this path when a maintainer owns the fix and no external collaborator needs
repository access:

#. Keep the report and disclosure coordination in the draft advisory.
#. Synchronize the shared security repository's ``master`` branch with the exact
   applicable public branch head.
#. Create ``sa/GHSA-xxxx-xxxx-xxxx`` directly in the shared security repository.
#. Implement the fix and tests on that branch.
#. Open a private pull request for maintainer review and CI.
#. Record the advisory, public base commit, candidate commit, and private CI run
   in the private pull request.
#. Keep the reporter informed through the advisory and request verification when
   practical.

This path does not create or use an advisory temporary fork. After it passes
review, the branch proceeds directly to required private validation or a
multi-advisory release train.

The direct path remains compatible with GitHub's security-advisory and CNA
workflow: a temporary fork is optional and is not required to request a CVE or
publish an advisory. Because the candidate commits were not created in the
advisory fork, do not use the advisory's **Merge pull requests** action. Record
the candidate commit in the private pull request, carry the reviewed commit
into the public release pull request, and add the final pull request, commit,
and release references to the advisory.

Collaborative temporary-fork path
---------------------------------

Use this path when the reporter or another external collaborator will develop or
review the patch:

#. Start the advisory's temporary private fork.
#. Develop and review the remediation with the external collaborator there.
#. Inspect the complete diff before running it in the shared security repository,
   especially workflow, dependency, build, and generated-file changes.
#. Fetch the advisory branch and verify that its commits descend from the expected
   public base.
#. Push the reviewed commits to the matching ``sa/GHSA-*`` branch in the shared
   security repository.
#. Open a private pull request and run maintainer validation there.
#. Record the advisory, public base commit, candidate commit, and private CI run
   in the private pull request.

Shared security repository conventions
======================================

Use the following branch conventions:

* ``master`` mirrors the public ``upstream/master`` branch.
* ``sa/GHSA-xxxx-xxxx-xxxx`` contains one advisory's candidate patch.
* ``security-release/<version>`` combines all patches intended for one release.

A maintainer using the direct path needs the public and security remotes:

.. code-block:: console

   git remote add upstream git@github.com:django-oauth/django-oauth-toolkit.git
   git remote add security git@github.com:django-oauth/django-oauth-toolkit-security.git

Add the advisory temporary fork as a third remote only for the collaborative
path:

.. code-block:: console

   git remote add advisory <temporary-fork-url>

Avoid rewriting commits after they pass private CI. If rewriting or rebasing is
necessary, rerun validation and record the replacement commit.

Required private validation
===========================

Each advisory branch must pass its targeted regression tests and all relevant
quality checks. The final release train must pass the complete supported matrix:

* Ruff lint and formatting checks.
* Sphinx lint and documentation build.
* SQLite across the supported Python and Django combinations.
* PostgreSQL standalone and primary/replica topologies.
* MySQL standalone and primary/replica topologies.
* Migration checks for each database topology.
* Multi-database and swapped-model migration scenarios.
* The demonstration relying-party build.
* OAuth/OIDC end-to-end compliance tests.
* Package build and ``twine check``.
* Installation and targeted smoke testing from the built wheel in a clean
  environment.

Private CI should exercise the same repository scripts, tox environments, and
Docker Compose definitions used by public CI. Repository-specific integrations
such as Codecov may be replaced with a successful no-op, but the tests
themselves must not be silently skipped.

Multi-advisory release trains
=============================

Maintainers may combine several ready fixes into one patched release.

#. Keep every patch on its own ``sa/GHSA-*`` branch for traceability.
#. Merge or cherry-pick the reviewed commits into
   ``security-release/<version>`` in a recorded order.
#. Resolve interactions in the release train rather than modifying another
   reporter's temporary fork.
#. Run the complete private validation matrix on the combined tree.
#. Ensure that every advisory names the intended release as its patched version.
#. If a patch is removed, reordered, rebased, or materially changed, rerun the
   complete release-train validation.

Do not delay a critical vulnerability merely to batch it with unrelated work.
Disclosure deadlines, active exploitation, and user impact take priority over a
convenient release train.

Final private release gate
==========================

Immediately before public promotion:

#. Briefly pause unrelated merges to the target public branch.
#. Fetch the latest public branch and record its commit.
#. Rebase or reconstruct the release train on that exact public head.
#. Resolve conflicts and rerun the complete private validation matrix.
#. Build the wheel and source distribution as a rehearsal and run
   ``twine check``.
#. Install the rehearsal wheel in a clean environment and run targeted security
   and OAuth/OIDC smoke tests.
#. Finalize the changelog, release version, release notes, advisory text,
   affected ranges, patched versions, CVE identifiers, mitigations, and credits.
#. Confirm that all reporters know the planned disclosure time.

The release coordinator records a private manifest containing:

* Included GHSAs and CVEs.
* Public base commit.
* Candidate commits and final tree hash.
* Private CI run and result.
* Planned release version.
* Reporter verification status.
* Planned public promotion and advisory publication times.

Public promotion and release
============================

Public promotion begins coordinated disclosure. Do not start it until the
release coordinator is prepared to monitor the complete release.

#. Push the final release-train commits to a branch in the primary public
   repository and open a focused public pull request. The embargo ends at this
   push.
#. Confirm that the public pull request's tree matches the privately validated
   tree. If GitHub produces a different commit SHA, compare the Git tree hashes.
#. Run the primary repository's complete public CI matrix.
#. Review any difference between private and public results. Infrastructure
   flakes may be rerun; code failures require a fix and renewed validation.
#. Merge only after the public CI result is green.
#. Tag the exact merged commit using the normal release convention.
#. Allow the primary repository release workflow to build, validate, and publish
   the wheel and source distribution to PyPI.
#. Verify that both artifacts are available from PyPI and install the published
   wheel in a clean environment.
#. Confirm that the GitHub release contains the intended security release notes.
#. Publish every included repository security advisory.
#. Verify the public GHSA and CVE identifiers, affected ranges, patched versions,
   credits, links, and mitigations.
#. Announce the release through the project's normal communication channels.

The public package must be built by the primary repository. Rehearsal artifacts
from the private security repository must never be uploaded to PyPI.

Failure during public cutover
=============================

Once a patch has been pushed publicly, do not assume that deleting a branch,
closing a pull request, or using an uninformative message restores its embargo.

If public CI fails:

* Assess whether the failure is infrastructure-only or a defect in the release
  candidate.
* Fix forward promptly and rerun the appropriate validation.
* Publish the advisory and mitigations without waiting for a package when users
  need information to protect themselves.

If package publication fails:

* Do not overwrite or replace files already uploaded to PyPI.
* Determine whether the same version can be safely retried without conflicting
  files. If not, increment the version and prepare a new release.
* Keep users informed through the advisory when the fixed package is delayed.

If advisory publication fails after the package is released:

* Publish explicit security release notes.
* Retry or complete publication through the GitHub advisory interface.
* Correct advisory metadata promptly after publication when necessary.

Post-release work
=================

#. Confirm that installing the patched version from PyPI resolves the reported
   behavior.
#. Verify that the advisory is present in the GitHub Advisory Database and that
   its package metadata is accurate.
#. Thank and credit the reporter according to their preference.
#. Update the advisory if later investigation changes the affected range,
   severity, mitigation, or patched version.
#. Delete completed ``sa/GHSA-*`` and ``security-release/*`` branches according
   to the repository retention policy. GitHub deletes the advisory temporary
   fork when the advisory is published.
#. Remove temporary access that is no longer required.
#. Record follow-up hardening, test, documentation, or process improvements in
   public issues when they do not disclose additional risk.
#. Review this runbook after each security release and update it through the
   normal public pull request process.
