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
| `Identity` | ✅ | Global users, federated identity links (idempotent provisioning), sessions (start/active/revoke/revoke-all, expiry), argon2-capable password auth. Events + audit. Ships `InteractsWithIdentity`. 9 tests. **Follow-up:** TOTP MFA, passkeys/WebAuthn, magic-link (tracked). |
| `Federation` | ⬜ | SAML/OIDC SP (wraps vetted XML/crypto libs). |
| `Directory` | ⬜ | SCIM 2.0 server. |
| `OAuthServer` | ⬜ | OIDC/OAuth provider on league/oauth2-server. |
| `AccessControl` | ⬜ | RBAC + Cashier-fed entitlements + decision surface. |
| `AuditQuery` | ⬜ | Read/query + SIEM streaming. |
| `Webhooks` | ⬜ | Signed delivery + retries. |
| `Api` | ⬜ | REST surface + OpenAPI. |

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
