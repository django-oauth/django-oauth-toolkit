# Table 4 — Relying Party (client) comparison

> Part of the [IDP compliance & competitive comparison](./README.md). Last verified **2026-07**.

The **Relying Party (RP)** is the *client* role — the application that logs users in
*through* an external OpenID Provider and consumes the resulting ID token. This is a
**different product category** from the authorization servers in
[Table 1](./idp-op-comparison.md), so it gets its own competitor set (client libraries)
and its own capability rows (the client-side obligations).

> **Django OAuth Toolkit is not a Relying Party.** DOT is an OAuth2/OIDC *provider*
> (authorization server + resource server). It does not consume external identity, so it
> is **N/A** in every row here. In a Django project you would pair DOT (as your OP) with a
> separate RP library (e.g. mozilla-django-oidc or django-allauth) if you also needed to
> *consume* another IdP. That DOT scores N/A here is the expected, correct result — it
> shows the boundary of what DOT is for.

## Legend

✅ Full · ◑ Partial / manual wiring · ❌ None · ❓ Unverified · **N/A** not applicable
(DOT is not an RP)

## RP capability matrix

Columns: **DOT** (not an RP) · **allauth** = django-allauth · **moz-oidc** =
mozilla-django-oidc · **Authlib** (client) · **PSA** = python-social-auth · **Auth.js** =
Auth.js / NextAuth · **oidc-ts** = oidc-client-ts · **Passport** = passport-openidconnect ·
**Spring** = Spring Security OAuth2 Client.

| RP capability | DOT | allauth | moz-oidc | Authlib | PSA | Auth.js | oidc-ts | Passport | Spring |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| OIDC Core — build request, **validate ID token**, userinfo | N/A | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| OIDC Discovery — auto-fetch OP metadata | N/A | ✅ | ◑ | ✅ | ✅ | ✅ | ✅ | ◑ | ✅ |
| WebFinger issuer discovery | N/A | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Dynamic client registration (self-register) | N/A | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| PKCE (client generates verifier) | N/A | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `state` / `nonce` validation | N/A | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Native-app redirect (RFC 8252, loopback/scheme) | N/A | ❌ | ❌ | ❓ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Refresh token handling / rotation | N/A | ◑ | ◑ | ✅ | ◑ | ◑ | ✅ | ◑ | ✅ |
| RP-Initiated Logout (redirect to end_session) | N/A | ❌ | ◑ | ◑ | ❌ | ◑ | ✅ | ❌ | ✅ |
| Front-Channel Logout (RP endpoint) | N/A | ❌ | ❌ | ❌ | ❌ | ❌ | ◑ | ❌ | ❌ |
| Back-Channel Logout (validate logout token) | N/A | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| PAR (RFC 9126, client pushes request) | N/A | ❌ | ❌ | ❓ | ❌ | ❓ | ❓ | ❌ | ❌ |
| DPoP (RFC 9449, sender-constrain) | N/A | ❌ | ❌ | ❓ | ❌ | ❌ | ✅ | ❌ | ◑ |
| private_key_jwt client auth (RFC 7523) | N/A | ❌ | ❌ | ✅ | ❌ | ◑ | ❌ | ❌ | ✅ |
| JARM (signed auth responses) | N/A | ❌ | ❌ | ❓ | ❌ | ❌ | ❓ | ❌ | ❓ |
| Multiple / social providers out of the box | N/A | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ◑ | ✅ |

## Reading this table

- **Django project needing to *consume* an IdP:** `mozilla-django-oidc` (single-OP,
  clean) or `django-allauth` (huge social-provider catalog) are the usual pairings
  alongside DOT-as-provider. `python-social-auth` also fits.
- **Most standards-complete RP libraries:** **Spring Security OAuth2 Client** (Java) is the
  broadest — it's the only one here with real **back-channel logout**, plus private_key_jwt
  and RP-initiated logout. **oidc-client-ts** leads on the browser/SPA side and is unusually
  the only RP with first-class **DPoP**.
- **Cross-library gaps:** WebFinger and self-service Dynamic Registration are absent
  everywhere; PAR and JARM are essentially unavailable on the RP side across the board.
- **Naming caution:** panva's `openid-client` (OpenID-certified, does PAR/DPoP/private_key_jwt)
  is a *different* package from jaredhanson's `passport-openidconnect` strategy scored here,
  which is much more limited. Auth.js uses panva's library under the hood but doesn't surface
  most of its advanced features.

> **Certification:** none of these eight libraries is currently listed as an OpenID-Certified
> *Relying Party* to our knowledge, but the OpenID certification directory could not be
> machine-read during research (the site blocked automated access), so this row is omitted
> rather than asserted. Verify at <https://openid.net/certification/> before relying on it.
