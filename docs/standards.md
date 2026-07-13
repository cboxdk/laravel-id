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
| M2M service accounts (client_credentials) — **overlap credential rotation**: mint a successor with the same privileges, cut over with zero downtime, then retire the predecessor (revoking its tokens) | ✅ |
| **RFC 8628** | Device Authorization Grant | ▢ |
| **RFC 9126** | Pushed Authorization Requests (PAR) | ▢ |

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
| Passwords — bcrypt, breached-password check (HIBP k-anonymity) | ✅ |
| TOTP (RFC 6238) — replay-protected (last-used step), rate-limited | ✅ |
| WebAuthn / passkeys (FIDO2) — registration + assertion, sign-count clone detection | ✅ |
| Passkey User-Verification enforced (primary-factor), server-side challenge TTL | ✅ |
| MFA recovery / backup codes — single-use, regenerable | ✅ |
| Magic-link email sign-in | ✅ |
| Password reset — hash-only single-use token, TTL, anti-enumeration, revokes all sessions on reset | ✅ |
| Email verification — hash-only single-use token, TTL, stale-address guard | ✅ |
| Social sign-in (Google, GitHub, Microsoft) with explicit account linking | ✅ |

*This table is updated as each tier lands; ▢ items are tracked and in progress.*
