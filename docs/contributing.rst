============
Contributing
============

By contributing you agree to abide by the `Code of Conduct <https://github.com/django-oauth/django-oauth-toolkit/blob/master/CODE_OF_CONDUCT.md>`_ and follow the `guidelines <https://django-oauth-toolkit.readthedocs.io/en/latest/contributing.html>`_.


Setup
=====

Fork ``django-oauth-toolkit`` repository on `GitHub <https://github.com/django-oauth/django-oauth-toolkit>`_ and follow these steps:

 * Create a virtualenv and activate it
 * Clone your repository locally

Issues
======

You can find the list of bugs, enhancements and feature requests on the
`issue tracker <https://github.com/django-oauth/django-oauth-toolkit/issues>`_. If you want to fix an issue, pick up one and
add a comment stating you're working on it.

Code Style
==========

The project uses `ruff <https://docs.astral.sh/ruff/>`_ for linting, formatting the code and sorting imports,
and `pre-commit <https://pre-commit.com/>`_ for checking/fixing commits for correctness before they are made.

You will need to install ``pre-commit`` yourself, and then ``pre-commit`` will
take care of installing ``ruff``.

After cloning your repository, go into it and run::

    pre-commit install

to install the hooks. On the next commit that you make, ``pre-commit`` will
download and install the necessary hooks (a one off task). If anything in the
commit would fail the hooks, the commit will be abandoned. For ``ruff``, any
necessary changes will be made automatically, but not staged.
Review the changes, and then re-stage and commit again.

Using ``pre-commit`` ensures that code that would fail in QA does not make it
into a commit in the first place, and will save you time in the long run. You
can also (largely) stop worrying about code style, although you should always
check how the code looks after ``ruff`` has formatted it, and think if there
is a better way to structure the code so that it is more readable.

Documentation
=============

You can edit the documentation by editing files in :file:`docs/`. This project
uses sphinx to turn ``ReStructuredText`` into the HTML docs you are reading.

In order to build the docs in to HTML, you can run::

    tox -e docs

This will build the docs, and place the result in :file:`docs/_build/html`.
Alternatively, you can run::

    tox -e livedocs

This will run ``sphinx`` in a live reload mode, so any changes that you make to
the ``RST`` files will be automatically detected and the HTML files rebuilt.
It will also run a simple HTTP server available at `<http://localhost:8000/>`_
serving the HTML files, and auto-reload the page when changes are made.

This allows you to edit the docs and see your changes instantly reflected in
the browser.

* `ReStructuredText primer
  <https://www.sphinx-doc.org/en/master/usage/restructuredtext/basics.html>`_

Translations
============

You can contribute international language translations using
`django-admin makemessages <https://docs.djangoproject.com/en/dev/ref/django-admin/#makemessages>`_.

For example, to add Deutsch::

    cd oauth2_provider
    django-admin makemessages --locale de

Then edit :file:`locale/de/LC_MESSAGES/django.po` to add your translations.

When deploying your app, don't forget to compile the messages with::

    django-admin compilemessages


Migrations
==========

If you alter any models, a new migration will need to be generated. This step is frequently missed
by new contributors. You can check if a new migration is needed with::

    tox -e migrations

And, if a new migration is needed, use::

    django-admin makemigrations --settings tests.mig_settings

Auto migrations frequently have ugly names like ``0004_auto_20200902_2022``. You can make your migration
name "better" by adding the ``-n name`` option::

    django-admin makemigrations --settings tests.mig_settings -n widget


Pull requests
=============

Please avoid providing a pull request from your ``master`` and use **topic branches** instead; you can add as many commits
as you want but please keep them in one branch which aims to solve one single issue. Then submit your pull request. To
create a topic branch, simply do::

    git checkout -b fix-that-issue
    Switched to a new branch 'fix-that-issue'

When you're ready to submit your pull request, first push the topic branch to your GitHub repo::

    git push origin fix-that-issue

Now you can go to your repository dashboard on GitHub and open a pull request starting from your topic branch. You can
apply your pull request to the ``master`` branch of django-oauth-toolkit (this should be the default behaviour of GitHub
user interface).

When you begin your PR, you'll be asked to provide the following:

* Identify the issue number that this PR fixes (if any).
  That issue will automatically be closed when your PR is accepted and merged.

* Provide a high-level description of the change. A reviewer should be able to tell what your PR does without having
  to read the commit(s).

* Make sure the PR only contains one change. Try to keep the PR as small and focused as you can. You can always
  submit additional PRs.

* Any new or changed code requires that a unit test be added or updated. Make sure your tests check for
  correct error behavior as well as normal expected behavior. Strive for 100% code coverage of any new
  code you contribute! Improving unit tests is always a welcome contribution.
  If your change reduces coverage, you'll be warned by `Codecov <https://codecov.io/>`_.

* Update the documentation (in `docs/`) to describe the new or changed functionality.

* Update ``CHANGELOG.md`` (only for user relevant changes). We use `Keep A Changelog <https://keepachangelog.com/en/1.0.0/>`_
  format which categorizes the changes as:

  * ``Added`` for new features.

  * ``Changed`` for changes in existing functionality.

  * ``Deprecated`` for soon-to-be removed features.

  * ``Removed`` for now removed features.

  * ``Fixed`` for any bug fixes.

  * ``Security`` in case of vulnerabilities. (Please report any security issues to the
     security team ``<django-oauth-security@googlegroups.com>``. Do not file an issue on the tracker
     or submit a PR until directed to do so.)

* Make sure your name is in :file:`AUTHORS`. We want to give credit to all contributors!

If your PR is not yet ready to be merged mark it as a Work-in-Progress
By prepending ``WIP:`` to the PR title so that it doesn't get inadvertently approved and merged.

Make sure to request a review by assigning Reviewer ``django-oauth/django-oauth-toolkit``.
This will assign the review to the project team and a member will review it. In the meantime you can continue to add
commits to your topic branch (and push them up to GitHub) either if you see something that needs changing, or in
response to a reviewer's comments.  If a reviewer asks for changes, you do not need to close the pull and reissue it
after making changes. Just make the changes locally, push them to GitHub, then add a comment to the discussion section
of the pull request.

Pull upstream changes into your fork regularly
==============================================

It's a good practice to pull upstream changes from master into your fork on a regular basis, in fact if you work on
outdated code and your changes diverge too far from master, the pull request has to be rejected.

To pull in upstream changes::

    git remote add upstream https://github.com/django-oauth/django-oauth-toolkit.git
    git fetch upstream

Then merge the changes that you fetched::

    git merge upstream/master

For more information, see the `GitHub Docs on forking the repository <https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/fork-a-repo>`_.

.. note:: Please be sure to rebase your commits on the master when possible, so your commits can be fast-forwarded: we
    try to avoid *merge commits* when they are not necessary.

How to get your pull request accepted
=====================================

We really want your code, so please follow these simple guidelines to make the process as smooth as possible.

The Checklist
-------------

A checklist template is automatically added to your PR when you create it. Make sure you've done all the
applicable steps and check them off to indicate you have done so. This is
what you'll see when creating your PR::

  Fixes #

  ## Description of the Change

  ## Checklist

  - [ ] PR only contains one change (considered splitting up PR)
  - [ ] unit-test added
  - [ ] documentation updated
  - [ ] `CHANGELOG.md` updated (only for user relevant changes)
  - [ ] author name in `AUTHORS`

Any PRs that are missing checklist items will not be merged and may be reverted if they are merged by
mistake.


Run the tests!
--------------

Django OAuth Toolkit aims to support different Python and Django versions, so we use **tox** to run tests on multiple
configurations. At any time during the development and at least before submitting the pull request, please run the
testsuite via::

    tox

The first thing the core committers will do is run this command. Any pull request that fails this test suite will be
**immediately rejected**.

Add the tests!
--------------

Whenever you add code, you have to add tests as well. We cannot accept untested code, so unless it is a peculiar
situation you previously discussed with the core committers, if your pull request reduces the test coverage it will be
**immediately rejected**.

You can check your coverage locally with the `coverage <https://pypi.org/project/coverage/>`_ package after running tox::

  pip install coverage
  coverage html -d mycoverage

Open :file:`mycoverage/index.html` in your browser and you can see a coverage summary and coverage details for each file.

There's no need to wait for Codecov to complain after you submit your PR.

The tests are generic and written to work with both single database and multiple database configurations. tox will run
tests both ways. You can see the configurations used in tests/settings.py and tests/multi_db_settings.py.

When there are multiple databases defined, Django tests will not work unless they are told which database(s) to work with.
For test writers this means any test must either:
- instead of Django's TestCase or TransactionTestCase use the versions of those
  classes defined in tests/common_testing.py
- when using pytest's `django_db` mark, define it like this:
  `@pytest.mark.django_db(databases=retrieve_current_databases())`

In test code, anywhere the database is referenced the Django router needs to be used exactly like the package's code.

.. code-block:: python

    token_database = router.db_for_write(AccessToken)
    with self.assertNumQueries(1, using=token_database):
        # call something using the database

Without the 'using' option, this test fails in the multiple database scenario because 'default' will be used instead.

Debugging the Tests Interactively
---------------------------------

Interactive Debugging allows you to set breakpoints and inspect the state of the program at runtime. We strongly
recommend using an interactive debugger to streamline your development process.

VS Code
^^^^^^^

VS Code is a popular IDE that supports debugging Python code. You can debug the tests interactively in VS Code by
following these steps:

.. code-block:: bash

    pip install .[dev]
    # open the project in VS Code
    # click Testing (erlenmeyer flask) on the Activity Bar
    # select the test you want to run or debug



Code conventions matter
-----------------------

There are no good nor bad conventions, just follow PEP8 (run some lint tool for this) and nobody will argue.
Try reading our code and grasp the overall philosophy regarding method and variable names, avoid *black magics* for
the sake of readability, keep in mind that *simple is better than complex*. If you feel the code is not straightforward,
add a comment. If you think a function is not trivial, add a docstrings.

To see if your code formatting will pass muster use::

  tox -e lint

The contents of this page are heavily based on the docs from `django-admin2 <https://github.com/twoscoops/django-admin2>`_

Maintainer Checklist
====================
The following notes are to remind the project maintainers and leads of the steps required to
review and merge PRs and to publish a new release.

Reviewing and Merging PRs
-------------------------

- Make sure the PR description includes the `pull request template
  <https://github.com/django-oauth/django-oauth-toolkit/blob/master/.github/pull_request_template.md>`_
- Confirm that all required checklist items from the PR template are both indicated as done in the
  PR description and are actually done.
- Perform a careful review and ask for any needed changes.
- Make sure any PRs only ever improve code coverage percentage.
- All PRs should be be reviewed by one individual (not the submitter) and merged by another.

PRs that are incorrectly merged may (reluctantly) be reverted by the Project Leads.

End to End Testing
------------------

There is a demonstration Identity Provider (IDP) and Relying Party (RP) to allow for
end to end testing. They can be launched directly by following the instructions in
/test/apps/README.md or via docker compose. To launch via docker compose

.. code-block:: bash

    # build the images with the current code
    docker compose build
    # wipe any existing services and volumes
    docker compose rm -v
    # start the services
    docker compose up -d

Please verify the RP behaves as expected by logging in, reloading, and logging out.

open http://localhost:5173 in your browser and login with the following credentials:

username: superuser
password: password

Publishing a Release
--------------------

Only maintainers can publish a release to pypi.org
and rtfd.io. This checklist is a reminder of the required steps.

- When planning a new release, create a `milestone
  <https://github.com/django-oauth/django-oauth-toolkit/milestones>`_
  and assign issues, PRs, etc. to that milestone.
- Review all commits since the last release and confirm that they are properly
  documented in the CHANGELOG. Reword entries as appropriate with links to docs
  to make them meaningful to users.
- Make a final PR for the release that updates:

  - :file:`CHANGELOG.md` to show the release date.
  - :file:`oauth2_provider/__init__.py` to set ``__version__ = "..."``

- Once the final PR is merged, create and push a tag for the release. You'll shortly
  get a notification of the availability of two pypi packages (source tgz
  and wheel). Download these locally before releasing them.
- Do a ``tox -e build`` and extract the downloaded and built wheel zip and tgz files into
  temp directories and do a ``diff -r`` to make sure they have the same content.
  (Unfortunately the checksums do not match due to timestamps in the metadata
  so you need to compare all the files.)
- Once happy that the above comparison checks out, approve the releases to Pypi.org.
