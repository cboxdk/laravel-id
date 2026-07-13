# Changelog

All notable changes to `cboxdk/laravel-id` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Confirmed security vulnerabilities and their fixes are cross-referenced under
**Security** below and in the repository's security advisories.

## [Unreleased]

## [0.4.0] - 2026-07-13

A security-hardening pass from a full review. Isolation is now enforced by the
deny-by-default global scope across every tenant table rather than by per-query
discipline. Breaking: adds `environment_id` to several tables (schema change).

### Security

- **Environment isolation is now defense-in-depth.** `WebhookEndpoint` +
  `WebhookDelivery` were not environment-owned — a platform-wide (null-org)
  endpoint received *every* environment's events (cross-environment payload
  leak). Both are now environment-owned, and 13 more tenant-relevant tables
  gained the global scope (`DirectoryUser/Group`, `WebAuthnCredential`,
  `MfaFactor`, `MfaRecoveryCode`, `MagicLinkToken`, `PasswordResetToken`,
  `EmailVerificationToken`, `AccessToken`, `ServiceAccount`,
  `PushedAuthorizationRequest`, `Role`, `RoleAssignment`, `SamlAuthRequest`), so
  a query that forgets its filter can no longer cross environments. Replay tables
  (`DpopProof`, consumed SAML assertions) and the shared permission catalog stay
  global by design.
- **Device-grant redemption** flips `approved → redeemed` under `lockForUpdate`
  in a transaction, closing a single-use TOCTOU for a shared/logged `device_code`.
- **SAML Single Logout** scopes its identity lookup by `connection_id` (as login
  does), so a signed `LogoutRequest` from one connection can't force-logout a user
  belonging to another.
- **Magic-link redemption** locks the token row.
- **Credential checks** run a constant-cost dummy verify on the miss path
  (`Subjects`, `PlatformOperators`) — no username-enumeration timing oracle.
- **Host-based environment resolution** only trusts a leading subdomain label
  under a configured `cbox-id.environments.base_domains`; a spoofed `Host` can no
  longer select a plane.
- **Tenancy context managers** are `scoped`, not `singleton`, so a killed
  Octane worker can't leak a suspension counter across requests and collapse
  scoping.
- The configured `cbox-id.models.user` **must extend the package `User`** (which
  carries `BelongsToEnvironment`), so a host override can't silently unscope the
  users table.

### DX

- Docs: the flagship examples referenced a non-existent `UserDirectory` contract
  — renamed to `Subjects`/`DatabaseSubjects` across the README and docs so they
  run as written.
- Added `Platform/Testing/InteractsWithPlatform` (`makeOperator()`), dogfooded in
  the Platform tests, and a `Kernel/Crypto/Testing/FakeSecretBox` so hosts can
  test secret-sealing without libsodium.
- `@throws` tags on `Subjects` and `DeviceAuthorization`.

## [0.3.2] - 2026-07-13

### Fixed

- **`OrganizationHierarchy::move()` now syncs the `parent_id` column.** 0.3.1
  rewrote only the closure table, leaving the denormalized direct-parent column
  stale — so tree views built from `parent_id` didn't reflect a move. `move()`
  now updates both representations atomically.

## [0.3.1] - 2026-07-13

### Added

- **`OrganizationHierarchy::move()`** — reparent an existing organization, with
  its whole subtree, under a new parent (or promote to root). Rewrites the
  closure table correctly at any depth and throws `CannotReparent` if the target
  is the node itself or one of its descendants (cycle guard). Fills the gap that
  `attach()` — create-time only — left for tenant hierarchy management (moving a
  customer between resellers, restructuring OUs).

## [0.3.0] - 2026-07-13

Adds **platform operators** — the identity above every environment (the WorkOS
"team member" / developer account). Operators authenticate once at the platform
level and can then assume any environment's console, without needing an account
inside each plane.

### Added

- **Platform operators.** A new `platform_operators` table and
  `Cbox\Id\Platform\Contracts\PlatformOperators` repository. Operators are *not*
  environment-owned — no `environment_id`, globally unique email — so they resolve
  identically from any environment (asserted in the `@group isolation` suite).
  Password verification is gated on active status. `PlatformServiceProvider` binds
  the repository; a new migration ships the table.
- **Docs.** `core-concepts/platform-operators.md` — the model, the WorkOS/Auth0/
  Okta mapping, provisioning, and the isolation guarantee.

### Fixed

- **`User` now hashes assigned passwords.** The model gained a `password => hashed`
  cast, so a raw `User::create(['password' => ...])` (seeders, factories) hashes
  with the configured driver instead of storing plaintext — which previously threw
  `This password does not use the Argon2id algorithm` at sign-in. The `Subjects`
  API, which hashes up front, is unaffected (the cast skips already-hashed values).

## [0.2.0] - 2026-07-13

Adds **environments** — the hard identity boundary above organizations
(staging/prod, per-product and white-label isolation), WorkOS-style. This is a
breaking change: the schema and query scoping change platform-wide.

### Added

- **Environments.** A first-class isolation layer above the organization tenant:
  its own user pool, signing keys, issuer and organization tree. Resolved per
  request from the host (`ResolveEnvironment` middleware + `EnvironmentResolver`;
  custom-domain or leading-subdomain-as-slug). See
  [Environments & the isolation model](core-concepts/environments.md).
- `Environment` model + `environments` table; `EnvironmentContext`,
  `EnvironmentScope`, `BelongsToEnvironment`, `EnvironmentOwned`,
  `GenericEnvironment`; `actingAsEnvironment*` test helpers.
- A dedicated cross-layer isolation suite (`--group=isolation`) proving the
  boundary across tenancy, crypto, identity and the OAuth surface.

### Changed (breaking)

- Every environment-owned model now carries `environment_id` and is scoped by a
  **deny-by-default** environment scope, independent of (and harder than) the
  organization scope: `withoutScope`/roll-up on the org dimension never crosses an
  environment.
- **User email uniqueness is now per environment** (`(environment_id, email)`),
  and federated-link uniqueness includes the environment — the same email is a
  distinct user across environments.
- **Signing keys, JWKS and the issuer are per environment** — a token signed in
  one environment never verifies in another.
- API requests must resolve an environment from the host. Set
  `cbox-id.environments.default` for single-tenant/on-prem; a multi-tenant
  deployment refuses an unknown host.

## [0.1.2] - 2026-07-13

### Fixed

- Accept the canonical single-slash private-use redirect URI form
  (`com.example.app:/cb`) at registration, so native mobile apps (RFC 8252 /
  AppAuth) register cleanly.

## [0.1.1] - 2026-07-13

### Security

- Hardening pass: SAML `InResponseTo` enforcement, DPoP enforced at the resource
  surface and bound to refresh tokens, account-status gating across all login
  paths, step-up on MFA enrollment / provider unlink, webhook DNS pinning +
  dead-lettering, admin-only console reads, and per-client token ownership on
  introspection/revocation.

### Changed

- Documentation restructured into the topic-folder layout.

## [0.1.0] - 2026-07-13

First tagged release. Pre-1.0: the public API may still change between `0.x`
releases, and only the latest `0.x` tag is supported.

### Added

- **OAuth 2.0 / OIDC authorization server** — `authorization_code` with mandatory
  PKCE (S256), `client_credentials`, refresh tokens with rotation + reuse
  detection (family revocation), and the Device Authorization Grant (RFC 8628).
- **Sender-constrained tokens (DPoP, RFC 9449)** — proof validation at the token
  endpoint, enforcement at the resource surface (`cnf.jkt` + `ath`), and DPoP-key
  binding of refresh tokens.
- **Pushed Authorization Requests** (RFC 9126) and a **FAPI 2.0 baseline** profile.
- **Token endpoint hardening** — `at+jwt` access tokens (RFC 9068), RFC 8707
  resource indicators with `invalid_target` rejection of malformed values, and
  the RFC 9207 `iss` authorization-response parameter.
- **Introspection (RFC 7662) and revocation (RFC 7009)** with per-client token
  ownership enforcement.
- **Discovery** — Authorization Server Metadata (RFC 8414), Protected Resource
  Metadata (RFC 9728), Dynamic Client Registration (RFC 7591/7592), and JWKS.
- **Token signing** — RS256, ES256 and EdDSA (Ed25519, RFC 8037) with `kid`-overlap
  key rotation.
- **UserInfo** endpoint and `id_token` claims (`at_hash`, `auth_time`, `acr`, `amr`,
  `nonce`).
- **Federation** — SAML 2.0 SP (metadata, SP-initiated login, SLO, InResponseTo
  enforcement) and OIDC as a relying party (with `nonce`).
- **Directory sync (SCIM 2.0)** — Users, Groups + membership, the Enterprise User
  extension, and PATCH (including `remove`); deprovisioning deactivates the
  account and revokes sessions.
- **Identity** — sessions with idle + absolute timeout and step-up, password auth,
  MFA (TOTP, recovery codes, WebAuthn/passkeys with user-verification), magic
  links, password reset, email verification, and account-status gating.
- **Organizations & tenancy** — deny-by-default tenant isolation, memberships with
  last-owner protection, and a closure-tree hierarchy.
- **Authorization** — a policy decision point, ReBAC relationship store, and
  entitlements as capability gates (hybrid token-claim / decision-endpoint model).
- **Webhooks** — HMAC-signed delivery with SSRF-guarded, DNS-pinned requests,
  bounded retries with dead-lettering, and a scheduled retry sweep.
- **Audit** — an append-only, hash-chained trail with signed checkpoints.

### Security

- Fixed a cross-tenant account-takeover vector in federated identity linking:
  SSO connection identities are now namespaced to their connection.
- Enforced SAML `InResponseTo` against a request store, DPoP at the resource
  surface and on refresh tokens, account-status gating across all login paths,
  step-up on MFA enrollment and provider unlink, and admin-only reads on the
  console. See the security advisories for detail.
