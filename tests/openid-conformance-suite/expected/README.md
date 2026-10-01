# Calibration files

One pair of files per plan name in `run.py`'s `PLANS`, in the runner's own format:

* `<name>.failures.json`: conditions expected to fail or warn (`test-name`, `variant`,
  `configuration-filename` glob, `condition`, `expected-result`, a `comment` saying why).
  `tox -e openid-conformance-suite -- --plan <name> --verbose` prints a ready-made entry
  for every unexpected failure.
* `<name>.skips.json`: modules the suite is expected to skip because the OP does not
  support what they test (`test-name`, `variant`, `configuration-filename`).

A file is passed only when it exists, and only for the plans being run, because the
runner fails a run whose entries match no module it ran. Add an entry only with a reason
that would survive review; a gap in `oauth2_provider` belongs in an issue, not here.
