---
title: Standards & conformance
description: Every RFC and specification the platform implements, and to what extent
weight: 8
---

# Standards & conformance

Cbox ID is built against the specifications, not around them. This page is the
canonical list of what is implemented. Status is one of **✅ implemented**,
**◐ partial** (usable, with the noted limits), or **▢ planned**.

## OAuth 2.0 / OpenID Connect (as an authorization server)

| Spec | What it covers | Status |
|------|----------------|--------|
| **RFC 6749** | Authorization Code (mandatory PKCE) + Client Credentials + Refresh Token grants | ✅ |
| **RFC 7636** | PKCE — `S256` required, `plain` refused | ✅ |
| **RFC 6750** | Bearer token usage | ✅ |
| **RFC 7519 / 9068** | JWT access tokens (RS256, `typ: at+jwt`), `jti`-tracked for revocation; `aud` when resource-bound | ✅ |
| **RFC 8725 (JWT BCP)** | Explicit alg allow-list (RS256 / ES256 / **EdDSA Ed25519**, RFC 8037), per-key alg binding, scheduled key rotation (`cbox-id:keys:rotate --alg`) | ✅ |
| **RFC 7662** | Token introspection — caller must authenticate as a client | ✅ |
| **RFC 7009** | Token revocation (`/oauth/revoke`) — access **and** refresh tokens | ✅ |
| **RFC 8414** | Authorization Server Metadata (`/.well-known/oauth-authorization-server`) | ✅ |
| **RFC 9728** | Protected Resource Metadata (`/.well-known/oauth-protected-resource`) | ✅ |
| **RFC 8707** | Resource Indicators — `resource` binds the access token's `aud` | ✅ |
| **RFC 7591** | Dynamic Client Registration (`/oauth/register`) — gated (disabled/protected/open) | ✅ |
| **RFC 7592** | Registration management (GET/PUT/DELETE by registration access token) | ✅ |
| **OIDC Core** | `id_token` with `nonce`, `at_hash`, `auth_time`, `amr`, `acr`; UserInfo endpoint | ✅ |
| **OAuth 2.0 Security BCP** | Refresh-token rotation with reuse detection (family revocation) | ✅ |
| **RFC 9449** | DPoP — sender-constrained tokens (`cnf.jkt`, `token_type: DPoP`); proof validated for typ/alg/signature/htm/htu/iat with single-use `jti` replay guard; advertised in metadata | ✅ |
| **RFC 9126** | Pushed Authorization Requests (`/oauth/par`) — client-authenticated, single-use short-lived `request_uri` consumed by `/authorize`; `require_pushed_authorization_requests` advertised | ✅ |
| **RFC 8628** | Device Authorization Grant (`/oauth/device_authorization`) — `user_code` (unambiguous alphabet) + `verification_uri`; token polling with `authorization_pending` / `slow_down` / `access_denied` / `expired_token`; device_code stored hashed | ✅ |
| **RFC 9207** | Issuer identification in the authorization response (`iss`) — IdP mix-up defense, always on | ✅ |
| **FAPI 2.0 baseline** | Enforceable profile: mandatory PAR + PKCE + DPoP sender-constraining + exact redirect matching + `iss` — see [FAPI hardening](fapi.md) | ✅ |
| M2M service accounts (client_credentials) — **overlap credential rotation**: mint a successor with the same privileges, cut over with zero downtime, then retire the predecessor (revoking its tokens) | ✅ |
| Authorization decision endpoint (`POST /oauth/decisions`) — live, deny-by-default permission (ReBAC) + entitlement checks in one round trip; version-invalidated hot-path cache; see [Authorization](../core-concepts/authorization.md) | ✅ |
| Hybrid entitlement claims — coarse `EnforcementMode::Claims` entitlements embedded as the `ent` claim (`ent_ver` staleness signal); instant-critical ones stay live | ✅ |

### Refresh tokens

Refresh tokens are issued only when the client is granted `offline_access`.
Every rotation is single-use: presenting a refresh token consumes it and mints a
successor in the same *family*. Presenting an already-consumed token is treated
as theft — the entire family is revoked, forcing re-authentication.

## Model Context Protocol (MCP)

The MCP authorization model expects the server to be a standards-compliant OAuth
2.0 authorization server. All five required pieces are in place:

| MCP requirement | Backed by | Status |
|-----------------|-----------|--------|
| Authorization Server Metadata | RFC 8414 | ✅ |
| Protected Resource Metadata | RFC 9728 | ✅ |
| Dynamic Client Registration | RFC 7591 | ✅ |
| PKCE | RFC 7636 | ✅ |
| Resource / audience binding | RFC 8707 | ✅ |

An MCP client can therefore discover the server, self-register, run an
authorization-code + PKCE flow, and receive an access token audience-bound to the
MCP server it intends to call.

## SCIM 2.0 (provisioning)

| Spec | What it covers | Status |
|------|----------------|--------|
| **RFC 7644** | `/Users` CRUD + PATCH (path and pathless), pagination, `scimType` errors | ✅ |
| **RFC 7643** | Core User schema | ✅ |
| **RFC 7644** | Filtering — `eq/ne/co/sw/ew/pr` (LIKE metacharacters escaped) | ◐ |
| **RFC 7643** | `/Groups` + membership sync (create/list/PATCH add-remove/PUT/delete) | ✅ |
| **RFC 7644** | ServiceProviderConfig / ResourceTypes / Schemas discovery | ✅ |
| **RFC 7643** | Enterprise User extension (`employeeNumber`, `costCenter`, `organization`, `division`, `department`, `manager`) — ingested, patched, returned, advertised in discovery | ✅ |

Deprovision / deactivation drops membership **and revokes sessions immediately**.

## SAML 2.0 & federation (as a relying party)

| Capability | Status |
|------------|--------|
| SAML ACS — signature (XML-DSig), XSW defense, XXE-safe, strict mode, `wantAssertionsSigned` | ✅ |
| SAML assertion replay protection (single-use assertion ids) | ✅ |
| SAML SP metadata endpoint (importable EntityDescriptor: ACS + SLO) | ✅ |
| SAML SP-initiated login (`AuthnRequest`, HTTP-Redirect, `InResponseTo` state, RelayState) | ✅ |
| SAML Single Logout — IdP-initiated `LogoutRequest`, **signed-message enforced**, revokes the subject's sessions, returns a `LogoutResponse` | ✅ |
| OIDC login (RP-initiated) — redirect + callback, code exchange, `id_token` verified (RS256-pinned), `state` CSRF + `nonce` replay defense | ✅ |

## Authentication & MFA

| Capability | Status |
|------------|--------|
| Passwords — hashed via the framework hasher (bcrypt/argon2id), verified through the pluggable `Subjects` resolver; password rules are an extension point | ✅ |
| TOTP (RFC 6238) — replay-protected (last-used step), rate-limited | ✅ |
| WebAuthn / passkeys (FIDO2) — registration + assertion, sign-count clone detection | ✅ |
| Passkey User-Verification enforced (primary-factor), server-side challenge TTL | ✅ |
| MFA recovery / backup codes — single-use, regenerable | ✅ |
| Magic-link email sign-in | ✅ |
| Password reset — hash-only single-use token, TTL, anti-enumeration, revokes all sessions on reset | ✅ |
| Email verification — hash-only single-use token, TTL, stale-address guard | ✅ |
| Federated sign-in — generic `FederatedPrincipal` provisioning + explicit account linking (`Subjects::link()`) | ✅ |

*This table is updated as each tier lands; ▢ items are tracked and in progress.*

**App-layer additions (not shipped by this package).** The following live in the
deployable app (cbox-id / `cboxdk/laravel-*` add-ons), built on the extension points
above — not in this framework's `src/`:

- **Breached-password screen** — HIBP k-anonymity check on password set/reset (the app
  implements the rule against the `Subjects` resolver).
- **Named social providers** — Google / GitHub / Microsoft sign-in via Laravel Socialite;
  the framework only provides the provider-agnostic `FederatedPrincipal` linking path.
- **Password policy** — e.g. a 12-char minimum and complexity rules, enforced in the app's
  auth views/rules.
