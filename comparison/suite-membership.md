# Table 2 — Suite → Spec membership (what each profile *is*)

> Part of the [IDP compliance & competitive comparison](./README.md). Last verified **2026-07**.

A "suite" (or profile) is **not a product** — it is a *named bundle of the individual
specifications*, with additional mandatory / optional / forbidden rules layered on top.
This table **defines** the common suites in terms of the spec rows used throughout this
comparison. It scores nobody; it is the shared vocabulary that lets
[Table 3 (suite rollup)](./suite-rollup.md) say "product X meets suite Y."

Read a column top-to-bottom to see what a profile requires. Read a row left-to-right to
see which profiles pull in a given spec.

## Legend

| Mark | Meaning |
|:---:|---|
| ● | **Required** — MUST implement to conform |
| ○ | **Optional / recommended** — MAY or SHOULD |
| ⊘ | **Forbidden** — MUST NOT use in this profile |
| *(blank)* | Not part of this profile |

Suites: **OAuth 2.0** (classic framework) · **OAuth 2.1** (consolidation draft) ·
**OIDC** (OpenID Connect Basic/Core) · **FAPI 2.0** (Financial-grade Security Profile) ·
**MCP** (Model Context Protocol authorization, 2025-06-18) · **Native** (OAuth for native
apps, RFC 8252) · **RP** (Relying-Party / client role).

## Membership matrix

Columns include the two client/API **roles** (RP, RS) alongside the provider profiles.

| Specification | OAuth 2.0 | OAuth 2.1 | OIDC | FAPI 2.0 | MCP | Native | RP | RS |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| RFC 6749 — OAuth 2.0 core | ● | ● | ● | ● | ● | ● | ● | ○ |
| — Implicit grant | ○ | ⊘ | ○ | ⊘ | ⊘ | ⊘ | ⊘ | |
| — Resource-owner password grant | ○ | ⊘ | | ⊘ | ⊘ | ⊘ | ⊘ | |
| RFC 6750 — Bearer token usage | ● | ● | ● | ● | ● | ● | ● | ● |
| RFC 7009 — Revocation | ○ | ○ | ○ | ○ | ○ | | ○ | |
| RFC 7636 — PKCE | ○ | ● | ○ | ● | ● | ● | ● | |
| RFC 7662 — Introspection | ○ | ○ | ○ | ○ | ○ | | | ○ |
| RFC 8252 — Native apps | ○ | ○ | | | ○ | ● | ○ | |
| RFC 8414 — AS metadata | ○ | ○ | ○ | ● | ● | ○ | ○ | ○ |
| RFC 8628 — Device grant | ○ | ○ | | | ○ | ○ | | |
| RFC 7591 — Dynamic client registration | ○ | ○ | ○ | ○ | ○ † | | ○ | |
| RFC 7592 — DCR management | ○ | | | | ○ | | ○ | |
| RFC 7519 — JWT | ○ | ○ | ● | ● | ○ | | ● | ○ |
| RFC 7523 — private_key_jwt | ○ | ○ | ○ | ○ ‡ | ○ | | ○ | |
| RFC 9068 — JWT access tokens (at+jwt) | ○ | ○ | | ○ | ○ | | | ○ |
| RFC 9126 — PAR | ○ | ○ | | ● | ○ | | ○ | |
| RFC 9396 — RAR | ○ | ○ | | ○ | ○ | | | |
| RFC 9449 — DPoP | ○ | ○ | | ○ ‡ | ○ | | ○ | ○ |
| RFC 8705 — mTLS client auth | ○ | ○ | | ○ ‡ | | | | ○ |
| RFC 8707 — Resource indicators | ○ | ○ | | ○ | ● | | ○ | ○ |
| RFC 9728 — Protected resource metadata | ○ | ○ | | ○ | ● | | ○ | ● |
| RFC 9700 — Security BCP | ○ | ● | ○ | ● | ● | ● | ○ | ○ |
| OIDC Core | | | ● | ○ | | | ● | |
| OIDC Discovery | | | ○ | ○ | | | ○ | |
| OIDC Dynamic Registration | | | ○ | | ○ | | ○ | |
| OIDC RP-Initiated Logout | | | ○ | | | | ○ | |
| OIDC Session Management | | | ○ | | | | ○ | |
| OIDC Front-Channel Logout | | | ○ | | | | ○ | |
| OIDC Back-Channel Logout | | | ○ | | | | ○ | |
| CIBA | | | ○ | ○ | | | | |

The **RS** column marks what a resource server touches: it MUST accept bearer tokens
(6750) and, for MCP, MUST publish protected-resource metadata (9728); it MAY validate JWT
(7519/9068), introspect (7662), and honor DPoP/mTLS/resource-indicators when the tokens use
them. See [Table 5](./rs-comparison.md).

† **MCP** treats Dynamic Client Registration as SHOULD (strongly recommended), not MUST.
‡ **FAPI 2.0** requires *sender-constrained* tokens via **either** mTLS (8705) **or** DPoP
(9449), and *client authentication* via **either** private_key_jwt (7523) **or** mTLS —
one of each pair is mandatory, which is why neither is marked ● alone.

## Profile rules in prose (the "layered on top" part)

The matrix captures *which specs* a profile pulls in; these are the behavioral rules a
matrix cell can't show:

- **OAuth 2.1** ([draft-ietf-oauth-v2-1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/))
  is not new specs — it *consolidates* OAuth 2.0 and: mandates PKCE for the authorization
  code flow, requires exact redirect-URI string matching, **removes the implicit grant**,
  **removes the resource-owner password grant**, and forbids bearer tokens in query
  strings. It effectively codifies the Security BCP (RFC 9700).
- **FAPI 2.0** ([Security Profile](https://openid.net/specs/fapi-2_0-security-profile.html))
  builds on OAuth 2.1 and additionally **requires PAR**, **requires sender-constrained
  tokens** (mTLS or DPoP), restricts client authentication to private_key_jwt or mTLS,
  requires the issuer identifier (RFC 9207) in the authorization response, and is
  authorization-code only. OIDC is commonly layered on but the security profile itself
  treats ID tokens as optional.
- **MCP authorization**
  ([2025-06-18 spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization))
  builds on OAuth 2.1. The **MCP server is an OAuth resource server**: it MUST publish
  Protected Resource Metadata (RFC 9728) pointing at its authorization server, clients
  MUST send the resource indicator (RFC 8707) so tokens are audience-bound, PKCE is
  mandatory, and Dynamic Client Registration SHOULD be supported. It does **not** require
  OpenID Connect — it is about authorization, not authentication.
- **Native** (RFC 8252) profiles the authorization-code flow for mobile/desktop apps: use
  an external user-agent (system browser), require PKCE, and handle loopback / custom-scheme
  redirect URIs.
- **RP** is the client role: build the authorization request, then **validate** the ID
  token (signature, `iss`, `aud`, `exp`, `nonce`) and manage `state`. Discovery, DCR, and
  the logout specs appear from the *consuming* side (the RP fetches metadata, self-registers,
  and exposes logout endpoints). See [Table 4](./rp-comparison.md).

These are deliberately simplified summaries. For conformance work, defer to the linked
profile specifications, which are authoritative.
