# Cbox ID — Build status

Living record of what is implemented, verified, and pending — built in dependency order.
"Verified" means: real tests green + PHPStan max clean + Pint clean. Nothing is marked done
on inspection alone. This file exists so the build is auditable: no hidden gaps.

Legend: ✅ done & verified · 🔨 in progress · ⏳ pending (blocked by a dependency) · ⬜ not started

**Milestone (2026-07-11 night): the entire kernel layer (5/5) is complete and verified** —
59 tests green, PHPStan level max clean, Pint clean, `composer audit` clean. Domain modules are
next; each starts with its step-0 contract PR against `docs/foundation-contracts.md`.

## Kernels
| Module | Status | Notes |
|---|---|---|
| `Kernel\Tenancy` | ✅ | Deny-by-default scope, cross-tenant write guard, runAs/withoutScope, **scopedTo(set) roll-up** for hierarchy. Ships `GenericTenant` + `Testing\InteractsWithTenancy`. 14 isolation tests. |
| `Kernel\Crypto` | ✅ | KeyManager (RS256/ES256, JWKS, rotation), TokenSigner (firebase/php-jwt, forced alg-allowlist — rejects `alg=none` / RS↔HS confusion / forgery / expiry), SecretBox (XChaCha20-Poly1305 AEAD envelope, context-bound). 15 tests. composer audit clean. |
| `Kernel\Audit` | ✅ | Append-only, per-scope hash chain (`SHA256(canonical(entry) ‖ prev_hash)`), deny-nothing tamper/deletion detection via `verifyChain`, Crypto-signed `checkpoint`. Ships `FakeAuditLog` + `InteractsWithAudit`. 11 tests incl. tamper + deletion detection. |
| `Kernel\Events` | ✅ | Transactional outbox: `emit` persists in the caller's tx (no dual-write, proven by a rollback test), durable `flushPending` relay dispatches `EventDelivered` at-least-once, idempotent. Ships `FakeEventBus` + `InteractsWithEvents`. 6 tests. |
| `Kernel\Authorization` | ✅ | Entitlements (billing-fed projection: set/revoke/reconcile, versioned+history, event+audit) · owned **ReBAC** tuple engine (direct + bounded recursive userset expansion, cycle-safe) · **PDP** (deny-by-default) delegating to both. Ships `InteractsWithEntitlements` + `InteractsWithAuthorization`. 14 tests. |

## Domain
| Module | Status | Notes |
|---|---|---|
| `Organization` | ✅ | Concrete `Tenant` (key = id) · closure-tree hierarchy (arbitrary depth: ancestors/descendants/isDescendantOf/`manages` for reseller transitive access) · memberships (tenant-scoped via `runAs`, dogfoods isolation) · events + audit. Ships `InteractsWithOrganizations`. 11 tests. |
| `Identity` | ✅ | Global users, federated identity links (idempotent provisioning), sessions (start/active/revoke/revoke-all, expiry), argon2-capable password auth. Events + audit. Ships `InteractsWithIdentity`. 9 tests. TOTP MFA ✅ (RFC 6238, verified against the RFC test vectors; secret sealed via Crypto). Passkeys ✅ (credential store + ceremony orchestration + **sign-count clone/replay detection**). **WebAuthn crypto ✅ (real):** `NativeWebAuthnVerifier` verifies registration + assertion signatures via **OpenSSL** (ES256/P-256 + RS256) with **CBOR/COSE decoded by vetted spomky-labs/cbor-php** — no hand-rolled crypto. Enforces ceremony type, challenge binding, origin + RP-id hash, user-presence; supports `none` + self-attestation `packed` (rejects unverifiable x5c chains). Bound only when `rp_id`/`origin` configured, else refuses. Tested against a **real software authenticator** (genuine EC/RSA keypairs, signed assertions) incl. tamper/wrong-challenge/foreign-origin/wrong-RP + end-to-end register→authenticate + clone detection. Magic-link ✅ (single-use hashed token → session, provisions user). |
| `Federation` | ✅ | ✅ Connections (per-org IdP config sealed via Crypto, per-connection routing, active-only resolution) + login orchestration (validated principal → user + membership + session; dogfoods Identity/Organization). **OIDC `AssertionValidator` ✅ (real crypto):** `id_token`/JWS verified via firebase/php-jwt with the key **pinned to RS256** (closes alg-confusion / `none`), `exp`/`nbf` enforced, `iss`/`aud` asserted, JWKS multi-key (`kid`) + single-key; tested against real generated RSA keypairs incl. unknown-key/wrong-iss/wrong-aud/expired/no-sub + end-to-end SSO. **SAML `AssertionValidator` ✅ (real crypto):** wraps `onelogin/php-saml` (XML-DSig verification, XSW defense, XXE-safe parsing) in strict mode with `wantAssertionsSigned`; tested against a genuinely XML-DSig-signed Response (via xmlseclibs + self-signed cert) incl. tamper/unsigned/wrong-audience/untrusted-key. Type-dispatching validator rejects any type with no registered validator (deny-by-default). 19 tests. |
| `Directory` | ✅ | SCIM provisioning core: directory registration (bearer token hashed), provision/update (→ local user via Identity + link + org membership), deactivate/deprovision → **drops membership + revokes sessions immediately**. Events + audit. Ships `InteractsWithDirectory`. 6 tests. **Follow-up:** SCIM HTTP endpoint + PATCH-semantics + filter parsing (Okta/Entra interop) land in the `Api` layer. |
| `OAuthServer` | ✅ | ✅ Clients + service accounts (secrets hashed, **overlap credential rotation**), **client-credentials/M2M** token issuance + introspection + revocation — stateless RS256 JWTs signed & alg-allowlist-verified by the Crypto kernel, `jti`-tracked for revocation. **Authorization-code + PKCE (S256)** ✅: single-use SHA-256-hashed codes, 60s TTL, transactional `lockForUpdate` exchange, exact `redirect_uri`/client match, constant-time PKCE + reuse/expiry rejection (`AuthorizationCodes` contract). **Now shipping:** refresh-token rotation (reuse detection → family revocation), **DPoP** sender-constraining, **Pushed Authorization Requests** (`PushedAuthorizationRequests`), **device grant** (`DeviceAuthorization`), **dynamic client registration** (`DynamicClientRegistration` + RFC 7592 management). Events + audit. Ships `InteractsWithOAuth`. **Host boundary:** the interactive browser **consent / authorize screen is provided by the deployable app** (cbox-id's `/oauth/authorize`), not this package — the package ships the protocol endpoints, tokens and decisions the UI drives. |
| `AccessControl` | ✅ | RBAC: roles + permissions + assignments; hierarchy-aware `can()`/`permissionsFor()` — roles roll DOWN from ancestor orgs (reseller management), never up/sideways. Events + audit. Ships `InteractsWithAccessControl`. 6 tests. (Entitlements live in the Authorization kernel.) |
| `AuditQuery` | ✅ | Authorized read surface over the audit trail: filter by action/actor, cursor (sequence) pagination, scope isolation (org vs system), and `since()` pull-stream for SIEM. 5 tests. (Setup reuses the Audit kernel's `InteractsWithAudit`.) |
| `Webhooks` | ✅ | Endpoint registry (secrets sealed via Crypto SecretBox) · HMAC-SHA256 signed HTTP delivery · failure recording + exponential-backoff retries · listens to `EventDelivered` (full Events→webhook fan-out proven end-to-end). Ships `InteractsWithWebhooks`. 6 tests. |
| `Api` | ✅ | ✅ Machine endpoints (HTTP-tested): `/.well-known/jwks.json`, OIDC + OAuth AS/protected-resource discovery, **`POST /oauth/token`** (authorization_code+PKCE → access_token + signed id_token; client_credentials), `POST /oauth/introspect`, `POST /oauth/revoke`, `GET|POST /oauth/userinfo`, `POST /oauth/par`, `POST /oauth/device_authorization`, dynamic client registration (`/oauth/register` + RFC 7592 management), `/up`. Per-request environment resolution via `ResolveEnvironment`. 11 tests. **SAML ACS ✅** (`POST /sso/saml/{connection}/acs`, unauthenticated — the XML signature is the auth): resolves the connection, validates via `AssertionValidator`, drives `FederationFlow` → session; onelogin's Destination/Recipient check is pinned to the connection's configured `sp_acs_url` (proxy-safe, host-independent). 5 HTTP tests incl. genuinely-signed happy path, untrusted-key/unknown/inactive/missing. **SCIM HTTP endpoint ✅ (full Okta/Entra lifecycle):** bearer-authed `/scim/v2/Users` — filtered **list** (`filter=userName/externalId eq …`, `startIndex`/`count` pagination, ListResponse; unsupported filters → `400 invalidFilter`), create, read, **PATCH** (active + core attributes via path & pathless value-object ops), **PUT** full replace, delete; deprovision revokes sessions end-to-end. 12 tests. **Host boundary:** the interactive OIDC **authorize / consent UI ships in the deployable app** (cbox-id's `/oauth/authorize`), not this package. **Still open:** a general REST CRUD surface + OpenAPI document. |

## DX standard (every module must ship this)
- **Interface-driven** — public behaviour behind `Contracts/` so it is mockable/swappable.
- **Shippable test helpers** in a `Testing/` namespace (Laravel `fake()`-style ergonomics), e.g.
  `InteractsWithTenancy` — consumers testing their own tenant-scoped code get first-class support.
- **Extension points documented** — overridable methods, container bindings, and simple value
  objects (e.g. `GenericTenant`) so the package is easy to extend and adopt piecemeal.
- The package's own tests **dogfood** these helpers, so the DX is proven, not asserted.

## Hierarchy model (arbitrary depth) — where it lives
- Kernel change (done): `scopedTo([keys])` bounded roll-up scope. Everything else is layered on top:
- `Organization`: org tree (`parent_id` + `organization_closure`), `type` (customer/reseller); intra-org
  `org_units` tree (`parent_id` + closure, scoped by `organization_id`); cycle + max-depth guards.
- `AccessControl`: transitive management via closure ancestor checks; entitlement roll-down via
  ancestor walk; management grants. Cross-org action is always authorized `runAs` + audit.

## Tracked integration points (deliberately deferred, not gaps)
These cannot be built before their dependency exists; wiring them is part of the dependent module.

- **Request tenant resolution** — middleware that sets the tenant from the authenticated
  session/token. Lands with `Identity` + `Api`.
- **Queue tenant propagation** — captured tenant key restored in the worker (jobs must not run
  tenant-less or the deny-by-default scope silently returns nothing). Needs a `Tenant` resolvable
  from a key → lands with `Organization`.
- **`withoutScope` auditing** — `Kernel\Audit` now exists. To keep the tenancy kernel dependency-free,
  this is a **call-site convention**: whoever suspends scoping records an `AuditEvent`. Enforced at the
  domain call sites (review + tests), not wired into the kernel.

## Verification commands (per package)
    composer install
    vendor/bin/pint --test        # style
    vendor/bin/phpstan analyse    # static, level max
    vendor/bin/pest               # tests
    vendor/bin/pest --group=isolation   # the load-bearing tenant-isolation proofs
