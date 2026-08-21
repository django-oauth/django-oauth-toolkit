Sessions
========

A ``Session`` is the OpenID Connect authentication session: the continuous
period during which an end user is authenticated at this authorization server
*via a particular user agent*.

One session spans every application the user signs into from that browser, and
it is identified by ``sid``, a UUID issued as the ``sid`` claim in ID tokens.

.. note::

   ``Session`` answers *"who is logged in, where"*. :doc:`authorizations` answers
   *"which act of consent produced these tokens"*. They are orthogonal axes over
   the same token chain, and revoking one is not the same operation as ending the
   other -- see `Termination is not revocation`_.

The ``sid`` is not the Django session key
-----------------------------------------

The Django session key is the authentication cookie value. It is a secret, it
must never reach a relying party, and it rotates on login. The ``sid`` is a
separate public identifier stored *inside* the Django session.

``Session.session_key`` records the Django session the OP session was minted
under, and is kept only as a correlation aid -- it is neither displayed nor
searchable in the admin.

The session is a database row rather than session state alone because
back-channel logout has to answer "which relying parties took part in this
session" *after* the Django session is gone, and cache-backed session stores
cannot be queried.

Lifecycle
---------

**Minted lazily.** Logging in does not create one; the first authorization
request after login does. The ``sid`` is then stored in the Django session, so
subsequent authorizations from the same user agent reuse it -- that reuse is
what makes one session span several relying parties.

**Terminated** when the user logs out of the OP (Django's ``user_logged_out``
signal), or from the admin. A terminated or expired session is never reused: the
next authorization mints a fresh one.

**Purged** by :ref:`cleartokens`, once no authorization references the session,
so the ``sid`` linkage outlives the session for as long as the authorizations
granted during it do.

Which flows have one
--------------------

Only flows that involve a user agent. The authorization code, hybrid and
implicit flows record the browser's session on the ``Authorization``. The device
flow records the session of the browser the user *approved the device in* -- the
verification page -- not the device's own, since the device is not a user agent
the user is authenticated in.

``password`` and ``client_credentials`` have no session, permanently:
``Authorization.session`` is NULL for them because those flows create no
authentication session at all, not because the data is missing.

``auth_time`` and ``max_age``
-----------------------------

The ``auth_time`` claim is taken from ``Session.authenticated_at``, recorded
when the user authenticated in *this* user agent.

It was previously taken from ``user.last_login``, which is user-global: signing
in on a phone refreshed the authentication freshness asserted to a relying party
in a laptop's session, which defeats ``max_age``. Requests with no session --
non-interactive flows, or sessions minted before this was deployed -- still fall
back to ``last_login``.

Termination is not revocation
-----------------------------

This is the pair most at risk of being conflated, so it is worth stating
plainly:

* **Revoking an** :doc:`Authorization <authorizations>` kills its token chains
  on every device. It does not log anyone out.
* **Terminating a Session** records that this user agent's authentication ended.
  It does not, by itself, revoke authorizations or the tokens issued under them.

Session-scoped revocation -- ending a session *and* revoking the token chains
granted during it, except those carrying ``offline_access`` -- is a policy
decision that belongs with RP-initiated and back-channel logout, and is not
implemented here.

Extending the model
-------------------

``Session`` is swappable, like the other toolkit models::

    from oauth2_provider.models import AbstractSession


    class MySession(AbstractSession):
        user_agent = models.TextField(blank=True)

Then point the setting at it::

    OAUTH2_PROVIDER_SESSION_MODEL = "my_app.MySession"

The usual ordering caveat applies: create and run the migration defining the
swapped model before setting ``OAUTH2_PROVIDER_SESSION_MODEL``.
