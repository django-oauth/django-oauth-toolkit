Authorizations
==============

An ``Authorization`` is a durable record of granted consent: the fact that a
user -- or a client acting on its own behalf -- authorized a client for a set of
scopes at a point in time, via a particular grant type.

:rfc:`6749#section-1.3` defines an *authorization grant* as the credential
representing the resource owner's authorization: the authorization code, the
resource owner's password, the client's own credentials, the device code. Those
credentials are transient and flow-specific, and Django OAuth Toolkit models two
of them (``Grant`` for the authorization code, ``DeviceGrant`` for the device
code). The ``Authorization`` model records the durable fact they all represent,
so that a token can be traced back to the act of consent that produced it,
whichever flow issued it.

Every flow that issues tokens records one, and the access, refresh and ID tokens
it issues carry an ``authorization`` foreign key back to it.

.. note::

   ``Authorization`` answers *"which act of consent produced these tokens"*. It
   is not a session: it does not record which browser the user was on, and
   revoking one does not log anyone out.

When an authorization is recorded
---------------------------------

=============================== ================================================================= ============
Flow                            When an ``Authorization`` is recorded                             ``user``
=============================== ================================================================= ============
Authorization code / hybrid     at approval; the ``Grant`` (code) row carries the foreign key and  set
                                hands it to the tokens at exchange
Implicit                        at approval; the tokens reference it directly, since the implicit  set
                                flow mints no authorization code
Device (:rfc:`8628`)            when the user approves the device on the verification page;        set
                                ``DeviceGrant`` references it
Resource owner password         at token issuance -- one per password login, since each login is   set
                                a distinct authorization event
``client_credentials``          one per client, reused across token requests: the consent is the   ``None``
                                client registration itself
Refresh token                   never -- refreshed tokens inherit the authorization the original   --
                                grant created, matching the RFC semantics of a refresh as a
                                re-presentation of that grant
=============================== ================================================================= ============

A grant type this toolkit does not recognise -- a custom grant added by a
:class:`~oauth2_provider.oauth2_validators.OAuth2Validator` subclass, or one
added by a later RFC -- records an ``Authorization`` under its protocol name, so
its tokens are never left with no lineage.

The client identity is a value, not a foreign key
-------------------------------------------------

``Authorization.client_id`` records the client the authorization was granted to,
as a value. ``Authorization.application`` is a *nullable* pointer to the
``Application`` registration backing that ``client_id``, if there is one.

A NULL ``application`` therefore means "this client has no provisioned
registration" -- it was derived (see :doc:`cimd`), or the registration has since
been deleted -- and not "we no longer know who this token belongs to". Deleting
an ``Application`` clears the pointer and keeps the record of the consent.

Revoking an authorization
-------------------------

``Authorization.revoke()`` revokes every token issued under the authorization,
on every device, and closes every outstanding credential that could still mint
tokens under it: an authorization code that was never exchanged is deleted, and
a device grant that was approved but not yet redeemed is denied.

Deletion is not a domain action. The token foreign keys use
``on_delete=RESTRICT``, so an authorization cannot be deleted while tokens issued
under it exist -- except through a cascade that is removing those tokens too,
such as deleting the user. Row deletion is reserved for :ref:`cleartokens`, once
every token is gone.

The Django admin reflects this: authorizations can be inspected and revoked
there, but not added, edited, or deleted.

Authorization code replay
-------------------------

An authorization code is no longer deleted when it is exchanged. The row is kept
and stamped with ``exchanged_at``, and :ref:`cleartokens` purges it once it
expires.

Retaining it is what makes a replay recognisable: a code presented a second time
is otherwise indistinguishable from a code that was never issued.
:rfc:`6749#section-4.1.2` and :rfc:`9700#section-4.5` call for revoking the
tokens previously issued on a replayed code, and Django OAuth Toolkit now does
so -- the replayed exchange is rejected and the code's whole ``Authorization`` is
revoked, which takes the refresh chain descending from it with it.

.. note::

   A deployment that overrides ``invalidate_authorization_code()`` to delete the
   grant row keeps working, but loses replay detection along with the row.

Extending the model
-------------------

``Authorization`` is swappable, like ``Application`` and the token models::

    from oauth2_provider.models import AbstractAuthorization


    class MyAuthorization(AbstractAuthorization):
        reviewed_by = models.ForeignKey(
            settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL
        )

Then point the setting at it::

    OAUTH2_PROVIDER_AUTHORIZATION_MODEL = "my_app.MyAuthorization"

The same ordering caveat as for the other swappable models applies: create and
run the migration defining the swapped model before setting
``OAUTH2_PROVIDER_AUTHORIZATION_MODEL``.

Reserved for Rich Authorization Requests
----------------------------------------

``Authorization.authorization_details`` is present but unused. :rfc:`9396` (Rich
Authorization Requests) describes what was granted in a shape that
``Authorization.scope`` -- space-separated scope strings -- cannot carry. The
column is reserved so that support can be added without a further migration of
every deployment's token tables; nothing writes or enforces it today.
