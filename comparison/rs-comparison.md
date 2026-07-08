# Table 5 — Resource Server (API-protection) comparison

> Part of the [IDP compliance & competitive comparison](./README.md). Last verified **2026-07**.

The **Resource Server (RS)** is the API-protection role: it accepts an access token on an
incoming request, **validates** it (signature/introspection, issuer, audience, expiry),
enforces **scopes**, and rejects what doesn't pass. It's a different product category from
the authorization servers in [Table 1](./idp-op-comparison.md) *and* from the client
libraries in [Table 4](./rp-comparison.md) — so it gets its own competitor set (API
middleware and gateways) and its own capability rows.

> **Django OAuth Toolkit is a real Resource Server** (unlike the RP role, where it's N/A).
> DOT protects Django/DRF APIs out of the box: it accepts bearer tokens, enforces scopes
> (`TokenHasScope`), and can validate tokens against a remote authorization server by
> introspection (`RESOURCE_SERVER_INTROSPECTION_URL`). Its gaps mirror its provider side —
> no local JWT/`at+jwt` validation (DOT tokens are opaque), no DPoP/mTLS sender-constraining,
> no protected-resource metadata. See [`docs/resource_server.rst`](../docs/resource_server.rst).

## Legend

✅ Full · ◑ Partial / manual wiring · 🧩 Via plugin/module (not core) · ❌ None · ❓ Unverified

The **DOT column is authoritative** (from source); DOT appears in every tier below as the
benchmark. Other columns are sourced from official docs/source — see
[Methodology](./README.md#methodology).

---

## 5a. DOT vs. Python / Django resource-server options

**Authlib** ResourceProtector · **DRF + PyJWT** (the DIY DRF pattern) · **FastAPI** security utilities.

| RS capability | DOT | Authlib | DRF + PyJWT | FastAPI |
|---|:---:|:---:|:---:|:---:|
| Bearer token acceptance (RFC 6750) | ✅ | ✅ | ◑ | ✅ |
| Local JWT validation — JWKS sig, iss/aud/exp (RFC 7519) | ❌ | ✅ | ✅ | ❌ |
| `at+jwt` access-token profile (RFC 9068) | ❌ | ✅ | ❌ | ❌ |
| JWKS fetch + key rotation/caching | ❌ | ◑ | ✅ | ❌ |
| Token introspection client (RFC 7662) | ✅ | ✅ | ❌ | ❌ |
| Scope enforcement | ✅ | ✅ | ◑ | ◑ |
| Audience validation | ◑ | ✅ | ✅ | ❌ |
| Resource indicators (RFC 8707) | ❌ | ❌ | ❌ | ❌ |
| DPoP-bound tokens (RFC 9449) | ❌ | ❌ | ❌ | ❌ |
| mTLS certificate-bound tokens (RFC 8705) | ❌ | ❌ | ❌ | ❌ |
| Protected resource metadata (RFC 9728) | ❌ | ❌ | ❌ | ❌ |
| WWW-Authenticate 401 challenge (RFC 6750) | ◑ | ✅ | ◑ | ✅ |
| AS metadata / discovery auto-config (RFC 8414) | ❌ | ◑ | ❌ | ❌ |

*Read:* **Authlib** is the most complete Python RS — the only one here covering both JWT
(RFC 9068) and opaque/introspection tokens with first-class scope checks. **DOT** is the
opaque-token/introspection RS with the best native Django/DRF integration, but does no local
JWT validation. **DRF + PyJWT** and **FastAPI** are DIY: PyJWT's `PyJWKClient` gives you the
best JWKS caching, but everything else is hand-wired.

---

## 5b. DOT vs. other-ecosystem resource-server libraries

**Spring Security Resource Server** (Java) · **ASP.NET Core JwtBearer** (.NET) ·
**express-oauth2-jwt-bearer** (Node, Auth0).

| RS capability | DOT | Spring RS | ASP.NET JwtBearer | express-jwt-bearer |
|---|:---:|:---:|:---:|:---:|
| Bearer token acceptance (RFC 6750) | ✅ | ✅ | ✅ | ✅ |
| Local JWT validation — JWKS sig, iss/aud/exp (RFC 7519) | ❌ | ✅ | ✅ | ✅ |
| `at+jwt` access-token profile (RFC 9068) | ❌ | ✅ | ◑ | ✅ |
| JWKS fetch + key rotation/caching | ❌ | ✅ | ✅ | ✅ |
| Token introspection client (RFC 7662) | ✅ | ✅ | ❌ | ❌ |
| Scope enforcement | ✅ | ✅ | ◑ | ✅ |
| Audience validation | ◑ | ✅ | ✅ | ✅ |
| Resource indicators (RFC 8707) | ❌ | ❌ | ❌ | ❌ |
| DPoP-bound tokens (RFC 9449) | ❌ | ✅ | 🧩 | ✅ |
| mTLS certificate-bound tokens (RFC 8705) | ❌ | ✅ | 🧩 | ❌ |
| Protected resource metadata (RFC 9728) | ❌ | ◑ | 🧩 | ❌ |
| WWW-Authenticate 401 challenge (RFC 6750) | ◑ | ✅ | ✅ | ◑ |
| AS metadata / discovery auto-config (RFC 8414) | ❌ | ✅ | ✅ | ✅ |

*Read:* **Spring Security Resource Server** is the standard-bearer — native DPoP (6.5+),
mTLS cert-binding (6.3+), introspection, and a protected-resource-metadata class (7.0). The
Auth0 **express** SDK is a strong JWT-only RS (DPoP on by default). **ASP.NET** is solid for
JWT but pushes introspection, DPoP, mTLS, and PRM to add-ons.

---

## 5c. DOT vs. API gateways / proxies (edge enforcement)

| RS capability | DOT | oauth2-proxy | Ory Oathkeeper | Kong | Envoy | Nginx |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Bearer token acceptance (RFC 6750) | ✅ | ◑ | ✅ | 🧩 | ✅ | 🧩 |
| Local JWT validation — JWKS sig, iss/aud/exp (RFC 7519) | ❌ | ◑ | ✅ | 🧩 | ✅ | 🧩 |
| `at+jwt` access-token profile (RFC 9068) | ❌ | ❌ | ❓ | ❓ | ❌ | ❓ |
| JWKS fetch + key rotation/caching | ❌ | ◑ | ✅ | 🧩 | ✅ | 🧩 |
| Token introspection client (RFC 7662) | ✅ | ❌ | ✅ | 🧩 | ◑ | 🧩 |
| Scope enforcement | ✅ | ◑ | ✅ | 🧩 | ◑ | ◑ |
| Audience validation | ◑ | ◑ | ✅ | 🧩 | ✅ | ◑ |
| Resource indicators (RFC 8707) | ❌ | ❌ | ❌ | 🧩 | ❌ | ❌ |
| DPoP-bound tokens (RFC 9449) | ❌ | ❌ | ❌ | 🧩 | ❌ | ❌ |
| mTLS certificate-bound tokens (RFC 8705) | ❌ | ❌ | ❌ | 🧩 | ◑ | ❌ |
| Protected resource metadata (RFC 9728) | ❌ | ❌ | ❌ | 🧩 | ❌ | ❌ |
| WWW-Authenticate 401 challenge (RFC 6750) | ◑ | ❌ | ◑ | 🧩 | ◑ | ◑ |
| AS metadata / discovery auto-config (RFC 8414) | ❌ | ✅ | ◑ | 🧩 | ❌ | 🧩 |

*Read:* **Kong** (OIDC + AI-MCP-OAuth2 plugins) is the most complete edge enforcer — the only
one here with DPoP, mTLS binding, and RFC 9728 metadata publishing (all via plugin, some
enterprise/preview). **Ory Oathkeeper** is the strongest general RS proxy (JWT + introspection
+ scope + audience, all first-class). **Envoy** has best-in-class native JWT validation but
delegates introspection (ext_authz) and scope (RBAC). **oauth2-proxy** and **core Nginx** are
weak as pure RS enforcers — oauth2-proxy is really a browser-SSO cookie proxy; Nginx needs
OpenResty/Plus modules.

---

## Where DOT stands as a Resource Server

DOT is a **capable opaque-token / introspection RS with the best Django-native ergonomics**,
and it's the natural choice when DOT is *also* your authorization server. Its RS gaps are the
same modern-security specs it lacks on the provider side: **local JWT / `at+jwt` validation,
DPoP and mTLS sender-constraining, and protected-resource metadata (RFC 9728)** — the last of
which is what an MCP resource server must publish. If you need those today, Authlib (Python),
Spring Security (Java), or Kong (edge) lead; DOT covers the common bearer-plus-scopes API case
cleanly.
