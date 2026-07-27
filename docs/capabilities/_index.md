---
title: Capabilities
description: What this package supports at a glance — the grading vocabulary, and the two full matrices
weight: 4
---

# Capabilities

"Do you support X?" answered in seconds. Two matrices sit behind this page:

- **[Standards & conformance](../security/standards.md)** — the RFC-by-RFC record:
  OAuth 2.0, OpenID Connect, SCIM 2.0, SAML 2.0, WebAuthn, TOTP, JOSE.
- **[Feature support](feature-support.md)** — everything that is not a wire protocol:
  identity, RBAC, directory sync, governance, audit, webhooks, the token vault, operations.

## How to read the grades

Both matrices use the same five grades, and every row is graded against code in **this
package's `src/`** — never against what the deployable app, an optional add-on, or a future
release does.

| Grade | What it means |
|---|---|
| **Full** | This package ships the whole capability as described, and its own test suite exercises it. |
| **Partial** | Usable, with a limit — and **the limit is named in the row**. A "partial" that does not say what is missing is a documentation bug; please report it. |
| **Contract only** | The interface ships; the shipped default refuses or does nothing. Nothing works until you bind an implementation. This is a deliberate extension point, not an oversight — but it is not a working feature either. |
| **Host-supplied** | This package ships the back-channel or the primitive; the interactive half — a screen, a redirect, a decision — is your application's to write. |
| **No** | Not implemented. Listed because adopters ask. |

Rows do not get promoted for being nearly done. If a capability is graded **Full**, there is
a file you can open and a test that runs.

## What this package is, and is not

`cboxdk/laravel-id` is a **library**: UI-free, domain-free primitives behind contracts. It is
not a running identity provider you can point a browser at.

The most consequential line that draws: **the package does not serve `/authorize`.** It ships
the token, introspection, revocation, registration, PAR, device, CIBA, discovery and JWKS
endpoints, plus the crypto and validation those enforce — but login, consent, and everything
decided *at* the authorization request belong to your application. Rows that depend on that
half are graded **Host-supplied** so you can see exactly what you still have to build.

> **Don't want to build the app layer?** There is a full, deployable application built on
> this framework — the **cbox-id app** — with the admin console, hosted login, consent screen
> and onboarding already implemented. This documentation covers the framework you would build
> on directly. See the [overview](../index.md) for the split.

## At a glance

| Area | Where it stands |
|---|---|
| **OAuth 2.0 authorization server** | Authorization-code + PKCE `S256`, client-credentials, refresh with rotation and reuse detection, device grant, CIBA (poll), token exchange, PAR, DPoP, introspection, revocation, dynamic client registration. No ROPC, no implicit, no mTLS, no JAR/JARM. |
| **OpenID Connect provider** | Discovery, JWKS, id_token, UserInfo, RP-initiated logout. Code flow only, `query` response mode only. No front-channel or back-channel logout. |
| **SAML 2.0 identity provider** | Signed assertions and responses, RSA-SHA256, both browser bindings, SP-initiated Single Logout, XSW-hardened. No assertion encryption outbound, no unsolicited SSO, no global logout fan-out. |
| **SAML 2.0 / OIDC relying party** | Per-organization SSO connections, replay-protected assertions, JIT provisioning, domain verification. Outbound `AuthnRequest`s are unsigned; the outbound OIDC leg has no PKCE. |
| **SCIM 2.0 provisioning server** | Users and Groups CRUD, PATCH, filtering, pagination, Enterprise User extension, full discovery. No sorting, no ETags, no `/Bulk`, no `/Me`. |
| **Outbound provisioning** | A generic SCIM 2.0 client with retries, circuit breaker and SSRF guard. **Users only — no group push**, and no vendor-specific connectors. |
| **Directory sync (inbound)** | SCIM push, plus Google Workspace and Microsoft Entra pull connectors. Deprovision revokes sessions immediately. |
| **Authentication factors** | Passwords with a real policy engine, TOTP, WebAuthn/passkeys, recovery codes, magic links, email OTP. No SMS channel ships; breach screening is contract-only. |
| **Authorization** | RBAC scoped to the organization hierarchy, plus a relationship-based (ReBAC) engine with real graph traversal, plus billing-fed entitlements — surfaced together over `POST /oauth/decisions`. No wildcard permissions, no role-inherits-role. |
| **Governance** | Access-certification campaigns and Segregation-of-Duties policies over roles and memberships. Entitlements and ReBAC tuples are out of scope for now. |
| **Audit** | Append-only SHA-256 hash chain with signed checkpoints, and outbound streaming to Splunk HEC, Elastic ECS, GELF, CEF or generic JSON — all over HTTP. |
| **Extensibility** | Every capability is a contract you can rebind, plus six inline hook points with per-hook fail policy and a signed, SSRF-guarded HTTP transport. |

Read the two matrices for the detail, and the caveats, behind every one of those lines.
