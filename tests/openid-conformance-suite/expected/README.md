# Calibration files

One pair of files per plan name in `run.py`'s `PLANS`, in the runner's own format:

* `<name>.failures.json`: conditions expected to fail or warn (`test-name`, `variant`,
  `configuration-filename` glob, `condition`, `expected-result`, a `comment` saying why).
  `tox -e openid-conformance-suite -- --plan <name> --verbose` prints a ready-made entry
  for every unexpected failure.
* `<name>.skips.json`: modules the suite is expected to skip because the OP does not
  support what they test (`test-name`, `variant`, `configuration-filename`).

A file is passed only when it exists, and only for the plans being run, because the
runner fails a run whose entries match no module it ran.

Failures entries marked `"baseline": true` record the toolkit's known conformance gaps so that
any regression fails CI; `../baseline.py` regenerates them from a runner log, and a change that
fixes a gap must remove its entries (the runner fails while they no longer match). Every other
entry is a hand-written waiver and needs a reason that would survive review: a feature the
toolkit deliberately does not implement, or something CI cannot exercise. A toolkit gap belongs
in the baseline and in an issue, never in a waiver.
