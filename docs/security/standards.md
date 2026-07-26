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
| **OIDC Core** | `id_token` with `nonce`, `at_hash`, `auth_time`, `amr`, `acr`; UserInfo endpoint. **`acr_values` and `max_age` are ENFORCED at `/authorize`, not merely echoed:** `max_age` compares the session's own age against the client's ceiling and returns `login_required` when it is exceeded (`max_age=0` demands a fresh authentication); `acr_values` is answered from `AuthenticationContextClass`, the one enum that also drives `acr_values_supported` in discovery and the `acr` claim, so the advertisement, the gate and the claim cannot drift apart. A class the server does not assert is refused rather than silently downgraded | ✅ |
| **RFC 6749 §3.3** | **A scope the client is not registered for is refused at `/authorize` with `invalid_scope`**, rather than accepted and quietly filtered down at mint time. A client that registered no scopes at all is exempt (it has declared no surface to check against). The `/oauth/token` response **echoes the granted `scope`**, so a narrowed grant is visible in the response instead of surfacing later as an unexplained 403 | ✅ |
| **OAuth 2.0 Security BCP** | Refresh-token rotation with reuse detection (family revocation) | ✅ |
| **RFC 9449** | DPoP — sender-constrained tokens (`cnf.jkt`, `token_type: DPoP`); proof validated for typ/alg/signature/htm/htu/iat with single-use `jti` replay guard; advertised in metadata | ✅ |
| **RFC 9126** | Pushed Authorization Requests (`/oauth/par`) — client-authenticated, single-use short-lived `request_uri` consumed by `/authorize`; `require_pushed_authorization_requests` advertised | ✅ |
| **RFC 8628** | Device Authorization Grant (`/oauth/device_authorization`) — `user_code` (unambiguous alphabet) + `verification_uri`; token polling with `authorization_pending` / `slow_down` / `access_denied` / `expired_token`; device_code stored hashed | ✅ |
| **RFC 9207** | Issuer identification in the authorization response (`iss`) — IdP mix-up defense, always on | ✅ |
| **FAPI 2.0 baseline** | Building blocks shipped: mandatory PAR, PKCE `S256`, DPoP, `private_key_jwt`, exact redirect matching, `iss`. **Not met:** tokens are signed `RS256` (the profile permits only `PS256`/`ES256`/`EdDSA`) and there is no switch to *require* sender-constrained tokens. Not certified — see [FAPI hardening](fapi.md) | ◐ |
| M2M service accounts (client_credentials) — **overlap credential rotation**: mint a successor with the same privileges, cut over with zero downtime, then retire the predecessor (revoking its tokens) | ✅ |
| Authorization decision endpoint (`POST /oauth/decisions`) — live, deny-by-default permission (ReBAC) + entitlement checks in one round trip; version-invalidated hot-path cache; **batch size capped per field by `cbox-id.oauth.decisions.max_batch` (default 50), over which the request is `422 batch_too_large`** — distinct from the `422 no_organization_context` returned when the token carries no `org` claim; see [Authorization](../core-concepts/authorization.md) | ✅ |
| Hybrid entitlement claims — coarse `EnforcementMode::Claims` entitlements embedded as the `ent` claim (`ent_ver` staleness signal); instant-critical ones stay live | ✅ |

### Scope: what the framework provides vs. the integrator

The framework ships the **back-channel and token machinery** — the token, introspection,
revocation, registration, PAR, device, and discovery endpoints, plus the crypto,
algorithm pinning, and PKCE/redirect/`aud` validation those enforce. The **interactive
front-channel** — the `/authorize` endpoint itself, login, consent, and session
management — is the host application's responsibility (the deployable **cbox-id app**
implements it). PKCE is enforced structurally regardless: an authorization code minted
without a `code_challenge` can never satisfy the exchange, so a host that forgets to
require PKCE fails closed, not open. Treat "OIDC provider" here as "a conformant OIDC
token endpoint + back-channel," not a drop-in hosted-login UI.

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
| **RFC 7643** | `/Groups` + membership sync (create/list/PATCH add-remove/PUT/delete). `members` is omitted from a `/Groups` **listing** unless the client asks for it with `?attributes=members` (RFC 7643 §7 `returned: "request"`); reading a single group still returns it | ✅ |
| **RFC 7644** | ServiceProviderConfig / ResourceTypes / Schemas discovery | ✅ |
| **RFC 7643** | Enterprise User extension (`employeeNumber`, `costCenter`, `organization`, `division`, `department`, `manager`) — ingested, patched, returned, advertised in discovery | ✅ |

Deprovision / deactivation drops membership **and revokes sessions immediately**.

Full endpoint reference, error semantics and the honest list of what is not
implemented: [Inbound SCIM provisioning server](../core-concepts/scim.md).

## SAML 2.0 & federation (as a relying party)

| Capability | Status |
|------------|--------|
| SAML ACS — signature (XML-DSig), XSW defense, XXE-safe, strict mode, `wantAssertionsSigned` | ✅ |
| SAML assertion replay protection (single-use assertion ids) | ✅ |
| SAML SP metadata endpoint (importable EntityDescriptor: ACS + SLO) | ✅ |
| SAML SP-initiated login (`AuthnRequest`, HTTP-Redirect, `InResponseTo` state, RelayState) | ✅ |
| SAML Single Logout (SP role) — an upstream IdP's `LogoutRequest`, **signed-message enforced**, revokes the subject's sessions, returns a `LogoutResponse` | ✅ |
| SAML Single Logout (IdP role) — a relying SP's `LogoutRequest`, signature verified against the SP cert (RSA-SHA256 pinned), revokes local sessions, returns a **signed** `LogoutResponse` to the SP's SLO endpoint | ✅ |
| OIDC login (RP-initiated) — redirect + callback, code exchange, `id_token` verified (RS256-pinned), `state` CSRF + `nonce` replay defense | ✅ |
| OIDC RP-Initiated Logout 1.0 — `end_session_endpoint`, verified `id_token_hint`, `post_logout_redirect_uri` allow-list (no open redirect), `state` round-trip | ✅ |

## Authentication & MFA

| Capability | Status |
|------------|--------|
| Passwords — hashed via the framework hasher (bcrypt/argon2id), verified through the pluggable `Subjects` resolver; password rules are an extension point | ✅ |
| Bulk import + lazy password-hash migration — import existing hashes (bcrypt/argon2 natively), verified through a deny-by-default `HashVerifier` registry, and upgraded to the platform hasher on first login; unknown formats refused, foreign formats added by wrapping a vetted library | ✅ |
| TOTP (RFC 6238) — replay-protected (last-used step), rate-limited | ✅ |
| WebAuthn / passkeys — registration + assertion (ES256/RS256), sign-count clone detection, real signature verification via OpenSSL | ✅ |
| Passkey User-Verification enforced (primary-factor), server-side challenge TTL | ✅ |
| WebAuthn **attestation** — `none` and self-attestation `packed` accepted; full attestation-statement chains (`x5c`) and FIDO Metadata Service / AAGUID allow-listing are **not** verified (unknown formats are refused, so this fails safe). Enterprise authenticator-provenance policies bind their own verifier. | ◐ |
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
