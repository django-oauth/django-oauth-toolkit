# Table 1 — Spec × Competitor matrix (Provider / Authorization-Server role)

> Part of the [IDP compliance & competitive comparison](./README.md). Last verified **2026-07**.

This is the **detail matrix**: one row per specification, one column per product, scored for
the **OAuth 2.0 authorization-server / OpenID-Provider (OP/AS)** role. The
[suite rollup (Table 3)](./suite-rollup.md) aggregates these rows into profile-level
verdicts; the [suite membership (Table 2)](./suite-membership.md) defines the profiles.

The **Django OAuth Toolkit column is authoritative** (scored from source — see the
[compliance page](../docs/compliance.rst)). Every other column is sourced from vendor docs,
project source, and the OpenID Foundation certification directory; see
[Methodology](./README.md#methodology). Cells marked ❓ could not be confirmed from a primary
source and should not be read as "no".

## Legend

✅ Full · ⚙ Opt-in (implemented, off by default) · ◑ Partial / limited · 🧩 Add-on, plugin,
or paid tier · ❌ None · ❓ Unverified

---

## 1a. Django OAuth Toolkit vs. open-source libraries & engines

**oauthlib** — the protocol engine DOT builds on (a library, you assemble the server).
**Authlib** — a Python OAuth/OIDC framework. **Authentik** — a Django-based IdP.

| Specification | DOT | oauthlib | Authlib | Authentik |
|---|:---:|:---:|:---:|:---:|
| RFC 6749 — OAuth 2.0 core | ✅ | ✅ | ✅ | ✅ |
| — Implicit grant *(deprecated)* | ✅ | ✅ | ✅ | ✅ |
| — Resource-owner password grant *(deprecated)* | ✅ | ✅ | ✅ | ✅ |
| RFC 6750 — Bearer usage | ✅ | ✅ | ✅ | ✅ |
| RFC 7009 — Revocation | ✅ | ✅ | ✅ | ✅ |
| RFC 7636 — PKCE | ✅ | ✅ | ✅ | ✅ |
| RFC 7662 — Introspection | ✅ | ✅ | ✅ | ✅ |
| RFC 8252 — Native apps | ◑ | ❌ | ❌ | ◑ |
| RFC 8414 — AS metadata | ✅ | ✅ | ✅ | ◑ |
| RFC 8628 — Device grant | ✅ | ❌ | ✅ | ✅ |
| RFC 7591 — Dynamic client registration | ⚙ | ❌ | ✅ | ❌ |
| RFC 7592 — DCR management | ⚙ | ❌ | ✅ | ❌ |
| RFC 7519 — JWT | ◑ | ◑ | ✅ | ✅ |
| RFC 7523 — private_key_jwt | ❌ | ❌ | ✅ | ❌ |
| RFC 9068 — JWT access tokens (at+jwt) | ❌ | ❌ | ✅ | ❌ |
| RFC 9126 — PAR | ❌ | ❌ | ❌ | ❌ |
| RFC 9396 — RAR | ❌ | ❌ | ❌ | ❌ |
| RFC 9449 — DPoP | ❌ | ❌ | ❌ | ❌ |
| RFC 8705 — mTLS client auth | ❌ | ❌ | ❌ | ❌ |
| RFC 8707 — Resource indicators | ❌ | ❌ | ❌ | ❌ |
| RFC 9728 — Protected resource metadata | ❌ | ❌ | ❌ | ❌ |
| RFC 9700 — Security BCP | ◑ | ◑ | ◑ | ◑ |
| OIDC Core | ⚙ | ◑ | ✅ | ✅ |
| OIDC Discovery | ⚙ | ❌ | ✅ | ✅ |
| OIDC Dynamic Registration | ◑ | ❌ | ✅ | ❌ |
| OIDC RP-Initiated Logout | ⚙ | ❌ | ✅ | ✅ |
| OIDC Session Management | ❌ | ❌ | ❌ | ❌ |
| OIDC Front-Channel Logout | ❌ | ❌ | ❌ | ✅ |
| OIDC Back-Channel Logout | ❌ | ❌ | ❌ | ✅ |
| CIBA | ❌ | ❌ | ❌ | ❌ |
| FAPI 1.0 / 2.0 | ❌ | ❌ | ❌ | ❌ |
| CIMD — Client ID Metadata Document *(draft)* | ◑ | ❌ | ❌ | ❌ |

*Read:* DOT and Authentik are complete, batteries-included servers; **oauthlib** is
deliberately a lower-level library (DOT supplies discovery, device flow, DCR, and OIDC on top
of it). **Authlib** covers more raw RFCs than DOT (notably private_key_jwt and at+jwt) but is
a framework you assemble, not a Django-native app. None in this tier is OpenID-certified.

---

## 1b. Django OAuth Toolkit vs. open-source IdP servers

| Specification | DOT | Keycloak | Ory Hydra | WSO2 IS | Zitadel | Janssen |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| RFC 6749 — OAuth 2.0 core | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| — Implicit grant *(deprecated)* | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| — Resource-owner password grant *(deprecated)* | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ |
| RFC 6750 — Bearer usage | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| RFC 7009 — Revocation | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| RFC 7636 — PKCE | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| RFC 7662 — Introspection | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| RFC 8252 — Native apps | ◑ | ◑ | ✅ | ◑ | ✅ | ✅ |
| RFC 8414 — AS metadata | ✅ | ✅ | ✅ | ✅ | ◑ | ✅ |
| RFC 8628 — Device grant | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| RFC 7591 — Dynamic client registration | ⚙ | ✅ | ✅ | ✅ | ❌ | ✅ |
| RFC 7592 — DCR management | ⚙ | ✅ | ✅ | ✅ | ❌ | ✅ |
| RFC 7519 — JWT | ◑ | ✅ | ✅ | ✅ | ✅ | ✅ |
| RFC 7523 — private_key_jwt | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| RFC 9068 — JWT access tokens (at+jwt) | ❌ | ◑ | ◑ | ✅ | ◑ | ✅ |
| RFC 9126 — PAR | ❌ | ✅ | ❌ | ✅ | ◑ | ✅ |
| RFC 9396 — RAR | ❌ | ❌ | ❌ | ✅ | ❓ | ✅ |
| RFC 9449 — DPoP | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ |
| RFC 8705 — mTLS client auth | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ |
| RFC 8707 — Resource indicators | ❌ | ◑ | ❌ | ❓ | ❌ | ❌ |
| RFC 9728 — Protected resource metadata | ❌ | ◑ | ❌ | ❓ | ❓ | ❓ |
| RFC 9700 — Security BCP | ◑ | ◑ | ◑ | ◑ | ◑ | ❓ |
| OIDC Core | ⚙ | ✅ | ✅ | ✅ | ✅ | ✅ |
| OIDC Discovery | ⚙ | ✅ | ✅ | ✅ | ✅ | ✅ |
| OIDC Dynamic Registration | ◑ | ✅ | ✅ | ✅ | ❌ | ✅ |
| OIDC RP-Initiated Logout | ⚙ | ✅ | ✅ | ✅ | ✅ | ✅ |
| OIDC Session Management | ❌ | ✅ | ❌ | ✅ | ❓ | ✅ |
| OIDC Front-Channel Logout | ❌ | ✅ | ✅ | ✅ | ❓ | ✅ |
| OIDC Back-Channel Logout | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| CIBA | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ |
| FAPI 1.0 / 2.0 | ❌ | ✅ | ❌ | ✅ | ❌ | ◑ |
| CIMD — Client ID Metadata Document *(draft)* | ◑ | ◑ | ❌ | ❓ | ❌ | ✅ |
| **OpenID-certified OP** | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |

*Read:* **Keycloak, WSO2, and Janssen** are the standards-completeness leaders (FAPI, CIBA,
DPoP, mTLS, full logout suite). **Ory Hydra** and **Zitadel** are intentionally leaner,
modern, OAuth-2.1-flavored servers (no ROPC), closer to DOT's surface area but with OIDC
certification and back-channel logout that DOT lacks. DOT's distinctive gaps versus this
whole tier: **OIDC certification, FAPI, DPoP, mTLS, private_key_jwt, at+jwt, PAR, and
back-channel logout.**

---

## 1c. Django OAuth Toolkit vs. commercial SaaS IdPs

| Specification | DOT | Okta | Auth0 | Entra ID | Ping |
|---|:---:|:---:|:---:|:---:|:---:|
| RFC 6749 — OAuth 2.0 core | ✅ | ✅ | ✅ | ✅ | ✅ |
| — Implicit grant *(deprecated)* | ✅ | ✅ | ✅ | ✅ | ✅ |
| — Resource-owner password grant *(deprecated)* | ✅ | ✅ | ✅ | ✅ | ✅ |
| RFC 6750 — Bearer usage | ✅ | ✅ | ✅ | ✅ | ✅ |
| RFC 7009 — Revocation | ✅ | ✅ | ◑ | ❌ | ✅ |
| RFC 7636 — PKCE | ✅ | ✅ | ✅ | ✅ | ✅ |
| RFC 7662 — Introspection | ✅ | ✅ | ❌ | ❌ | ✅ |
| RFC 8252 — Native apps | ◑ | ✅ | ✅ | ✅ | ✅ |
| RFC 8414 — AS metadata | ✅ | ✅ | ✅ | ✅ | ✅ |
| RFC 8628 — Device grant | ✅ | ✅ | ✅ | ✅ | ✅ |
| RFC 7591 — Dynamic client registration | ⚙ | ✅ | ✅ | ❌ | ✅ |
| RFC 7592 — DCR management | ⚙ | ✅ | ❌ | ❌ | ✅ |
| RFC 7519 — JWT | ◑ | ✅ | ✅ | ✅ | ✅ |
| RFC 7523 — private_key_jwt | ❌ | ✅ | ✅ | ✅ | ✅ |
| RFC 9068 — JWT access tokens (at+jwt) | ❌ | ◑ | ✅ | ◑ | ✅ |
| RFC 9126 — PAR | ❌ | ✅ | 🧩 | ❌ | ✅ |
| RFC 9396 — RAR | ❌ | ❓ | 🧩 | ❌ | ✅ |
| RFC 9449 — DPoP | ❌ | ✅ | ✅ | ❌ | ✅ |
| RFC 8705 — mTLS client auth | ❌ | ❌ | 🧩 | ◑ | ✅ |
| RFC 8707 — Resource indicators | ❌ | ❌ | ◑ | ◑ | ✅ |
| RFC 9728 — Protected resource metadata | ❌ | ❓ | ◑ | ❓ | ❓ |
| RFC 9700 — Security BCP | ◑ | ◑ | ◑ | ◑ | ◑ |
| OIDC Core | ⚙ | ✅ | ✅ | ✅ | ✅ |
| OIDC Discovery | ⚙ | ✅ | ✅ | ✅ | ✅ |
| OIDC Dynamic Registration | ◑ | ✅ | ✅ | ❌ | ✅ |
| OIDC RP-Initiated Logout | ⚙ | ✅ | ✅ | ✅ | ✅ |
| OIDC Session Management | ❌ | ❓ | ◑ | ❓ | ◑ |
| OIDC Front-Channel Logout | ❌ | ✅ | ✅ | ✅ | ✅ |
| OIDC Back-Channel Logout | ❌ | ❌ | 🧩 | ❌ | ✅ |
| CIBA | ❌ | ◑ | 🧩 | ❌ | ✅ |
| FAPI 1.0 / 2.0 | ❌ | ❌ | 🧩 | ❌ | ✅ |
| CIMD — Client ID Metadata Document *(draft)* | ◑ | ❌ | ❌ | ❌ | ❓ |
| **OpenID-certified OP** | ❌ | ✅ | ✅ | ✅ | ✅ |

*Read:* **Ping Identity** is the standards maximalist (FAPI 2.0 certified, full advanced
stack). **Auth0** matches it on paper but gates PAR, RAR, mTLS, CIBA, back-channel logout,
and FAPI behind its Enterprise / Highly-Regulated-Identity tiers (🧩). **Okta** is strong but
notably lacks a token-introspection endpoint's sibling — it *has* introspection but no mTLS —
and has committed to (not yet achieved) FAPI. **Microsoft Entra ID** is the outlier: no
standard revocation or introspection endpoint, no DCR, and several proprietary substitutes
(its own PoP instead of DPoP, resource/scope model instead of RFC 8707).

---

## Where Django OAuth Toolkit stands

DOT is a **solid, secure OAuth 2.0 core + opt-in OIDC** — competitive with the leaner
open-source servers on the classic feature set (all five grants, PKCE-by-default,
revocation, introspection, device flow, DCR, AS metadata). Its consistent deltas versus the
broader field, in rough priority order:

1. **OIDC certification** — every dedicated server/SaaS here is OpenID-certified; DOT is not.
2. **Modern security specs** — DPoP (9449), mTLS (8705), private_key_jwt (7523), at+jwt (9068).
3. **Advanced authorization** — PAR (9126), RAR (9396), resource indicators (8707).
4. **Logout completeness** — back-channel and front-channel logout, session management.
5. **Profiles** — FAPI and MCP, which the above gaps block (see [Table 3](./suite-rollup.md)).

These are the natural roadmap candidates if DOT wants to close the gap with the certified
open-source servers.
