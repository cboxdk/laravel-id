# Cbox ID — Build status

Living record of what is implemented, verified, and pending — built in dependency order.
"Verified" means: real tests green + PHPStan max clean + Pint clean. Nothing is marked done
on inspection alone. This file exists so the build is auditable: no hidden gaps.

Legend: ✅ done & verified · 🔨 in progress · ⏳ pending (blocked by a dependency) · ⬜ not started

## Kernels
| Module | Status | Notes |
|---|---|---|
| `Kernel\Tenancy` | ✅ | Deny-by-default scope, cross-tenant write guard, runAs/withoutScope, **scopedTo(set) roll-up** for hierarchy. Ships `GenericTenant` + `Testing\InteractsWithTenancy`. 14 isolation tests. |
| `Kernel\Crypto` | 🔨 | KeyManager, TokenSigner (alg-allowlist), SecretBox (AEAD envelope). Next. |
| `Kernel\Audit` | ⏳ | Hash-chained append-only log; checkpoint signing needs `Crypto`. |
| `Kernel\Events` | ⬜ | Transactional outbox. |
| `Kernel\Authorization` | ⬜ | PDP + owned ReBAC + entitlement projection. |

## Domain
| Module | Status | Notes |
|---|---|---|
| `Organization` | ⬜ | Concrete `Tenant`; unblocks queue tenant-propagation. |
| `Identity` | ⬜ | Users, sessions, MFA, passkeys, magic link. |
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
- **`withoutScope` audit hook** — the contract requires every scope suspension to be audited.
  Wire an automatic audit record once `Kernel\Audit` exists.

## Verification commands (per package)
    composer install
    vendor/bin/pint --test        # style
    vendor/bin/phpstan analyse    # static, level max
    vendor/bin/pest               # tests
    vendor/bin/pest --group=isolation   # the load-bearing tenant-isolation proofs
