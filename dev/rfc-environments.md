# RFC: Environments & the identity/tenancy hierarchy

**Status:** Draft — design only, nothing built. Purpose: lock the isolation model
*before* touching the three security-critical kernels (Tenancy, Crypto, Identity).

## 1. Context & goals

Today the platform has a single scoping dimension (`organization_id`), a **global**
user pool, **global** signing keys/issuer, and open self-service signup. That is
enough for one product / one plane, but not for the target model.

Goals:
1. **Environments** — staging/prod separation, and per-product isolation, as a
   first-class layer inside one control plane (WorkOS-style, not "spin up a whole
   new instance").
2. **Arbitrary-depth organization hierarchy** — companies → divisions →
   sub-departments → teams, Active-Directory-OU-style, with delegated admin and
   role inheritance. (Already supported; must be reconciled with environments.)
3. **Two topologies**, chosen by placement not code: shared identity across
   products (SSO), or isolated user DB per product/reseller.
4. **Deployment lockdown** — closed / invite-only / open signup.
5. **Billing/plan seam** per environment and per org (design-for, not build).

## 2. The model — mental map

| Layer | This design | Active Directory | WorkOS / Auth0 / Okta |
|---|---|---|---|
| Identity boundary (user pool, keys, issuer, branding) | **Environment** | Forest / Domain | WorkOS Environment / Auth0 Tenant / Okta Org |
| Org tree (any depth) | **Organization** closure-tree | **OU** tree (nested OUs) | Organizations (usually flat) |
| People | **User** via Membership at an org node | User in an OU | User |
| Apps | **Client / Product** (OAuth) | app / SPN | Application |

We are deliberately **deeper than the typical WorkOS/Auth0 flat "Organizations"** —
closer to **AD's nested OUs**: Company → Division → Department → Team, arbitrary depth.

## 3. Scoping hierarchy

```
Environment   ── hard boundary: own users, signing keys, issuer, discovery, branding
├── Users            ── pool, shared within the environment
├── Organizations    ── closure-tree, ANY depth (company → division → dept → team)
│   └── Memberships  ── user ↔ org node + role
└── Clients/Products ── OAuth apps
```

Two scoping mechanisms, two jobs:
- **`environment_id`** — the **HARD wall**. Deny-by-default, never crossed by any
  query, roll-up, or federated link.
- **Org closure + `scopedTo` roll-up / role roll-down** — the **SOFT hierarchy**,
  strictly *within* one environment.

## 4. Topologies (choice = placement, not code)

- **Shared identity across products** (main model): several products in the **same**
  environment → a user signs up once and gets SSO across all; a customer org's SSO
  connection serves every product in that environment.
- **Isolated per product / white-label reseller**: a product (or reseller) in its
  **own** environment → separate user DB, keys, issuer, branding — a standalone
  "remote IdP in a box".

You switch topology by placing the product in a shared vs. dedicated environment.
No code difference.

## 5. Organization hierarchy (AD-style), reconciled with environments

Already implemented: `organizations.parent_id` + `organization_closure`
(ancestor/descendant transitive closure, O(1) at any depth), `OrganizationHierarchy`
(`descendants()`/`ancestors()`), and `TenantContext::scopedTo()` for roll-up.

- **Delegated administration** (AD OU delegation): an admin at org node *N* manages
  *N* and everything under it — `scopedTo(descendants(N))`. A department admin
  cannot touch a sibling department or the parent company.
- **Role inheritance** (AD group-policy down the tree): a role granted at a higher
  node rolls **down** to descendants (hierarchy-aware roll-down in AccessControl).
- **Reseller** is just a position in this picture:
  - *Reseller-as-subtree* — a parent org managing its child customer orgs (shared
    environment: shared user pool + issuer). For resellers who resell *within* your
    platform.
  - *Reseller-as-environment* — its own environment (own keys/issuer/users/branding).
    A true white-label IdP. For resellers who need hard isolation.

**LOAD-BEARING INVARIANT:** the org hierarchy is **bounded by the environment**. The
closure never spans environments; `descendants()`/`ancestors()` return only
same-environment orgs; roll-up/roll-down can never reach another environment. A leak
here is the worst-case bug — the environment-scoped analogue of the cross-tenant SAML
takeover we already fixed.

## 6. Concrete changes per kernel

1. **Tenancy** — add `environment_id` as an **outer** scope above `organization_id`.
   `BelongsToTenant`/`TenantScope` gain an environment predicate that **always**
   applies — even inside `scopedTo()` (org roll-up) and `withoutScope()` (which only
   ever relaxes the *org* dimension, never the environment). New `EnvironmentContext`
   resolving the current environment, mirroring `TenantContext`.
2. **Identity** — users become environment-scoped: `users.environment_id`; email
   uniqueness **per environment**; `IdentityLink` (federated) scoped by
   (environment, connection) on top of the connection-scoping already hardened. The
   same email is a distinct user across environments (staging-Alice ≠ prod-Alice).
3. **Crypto** — signing keys, JWKS, `iss`, discovery **per environment**. `KeyManager`
   keyed by environment; `/.well-known/openid-configuration` served per environment; a
   staging token's `iss`/`kid` never validates in prod.
4. **Organization** — `organizations.environment_id`; all closure ops bounded by env.
5. **OAuth server** — clients, connections, directories gain the environment parent
   (already org-scoped); authorize/consent/token resolve the environment; `aud`/`iss`
   per environment.

## 7. Environment resolution

- **Host / custom domain** for the OAuth/OIDC surface (`staging.auth.you.com` vs
  `auth.you.com`) — the issuer must match the host, so host-based is natural.
- **Environment-scoped API key** for the management API.
- Recommendation: host-based for the auth surface, key-based for management. (Open for
  review — see §11.)

## 8. Deployment lockdown / signup modes

`cbox-id.signup.mode = closed | invite_only | open` (resolvable per environment):
- **`closed`** — no self-service; provision org + admins via CLI. Single-tenant lock;
  "no one hosts free on our domain."
- **`invite_only`** — join only via an Invitation token (already implemented); no
  new-org self-creation.
- **`open`** — public multi-tenant signup.

Separate the two capabilities: *join via invite* vs *create a new org*.

## 9. Billing / plan seam (design-for, not build)

Entitlements (`EntitlementReader`/`EntitlementWriter`) already exist. Scope them at:
- **Environment** — your own hosting plan (for whoever runs the multi-tenant version).
- **Organization** — your customers' plans.

The billing engine maps `plan → entitlement gates` (`feature.sso`, `seats.limit`,
`usage.over_quota`, …) and pushes via `EntitlementWriter`. The IdP never holds
plan/price/usage. Nothing new to build in the IdP beyond correct env/org scoping.

## 10. Security invariants (must hold; test like the tenant-isolation suite)

1. Every tenant-owned query is pinned to an environment; missing environment context
   returns **nothing** (deny-by-default), never everything.
2. Org closure never spans environments; roll-up/roll-down bounded by environment.
3. Federated links scoped by (environment, connection): an IdP in env A can't assert a
   subject that resolves in env B.
4. Signing keys/issuer are environment-local; cross-environment token validation fails.
5. Signup mode enforced at **both** the signup route and the org-creation path.

## 11. Build vs. reuse, and rough estimate

**Reuse (already there):** org closure-tree, `scopedTo`, entitlements seam,
invitations, connection-scoping (hardened), deny-by-default tenant scope.

**Build:** `environment_id` outer scope (Tenancy) · env-scoped users + email
uniqueness + federated linking (Identity) · env-scoped keys/issuer/discovery (Crypto)
· environment resolution · propagation to the OAuth surface · admin UI · isolation
test suite · signup-mode gate.

**Rough (one experienced dev):** signup lockdown ~1–2 days; environments ~2–4 weeks
(touches three security-critical kernels + a dedicated isolation test pass); billing
wiring ~1–2 days.

## 12. Open questions

- Environment resolution: host-only, or host + management-API-key hybrid?
- Do resellers ever need cross-environment visibility? (Default: no — keep the wall hard.)
- B2C (user with no org) inside an environment: a default "personal" org, or truly
  org-less membership?
- Per-environment branding/theming scope and precedence vs. per-org branding.
- Migration: existing single-plane data → a default environment (backfill
  `environment_id`), keeping the current deployment working.

---

## Build progress

- [x] **Phase 1 — Environment foundation (Tenancy kernel).** `Environment` /
  `EnvironmentOwned` contracts, `EnvironmentContext` (+manager, provisioning-only
  `withoutScope`), hard deny-by-default `EnvironmentScope` (independent of the org
  scope), `BelongsToEnvironment` trait, `GenericEnvironment`, exceptions, DI
  registration, and `actingAsEnvironment*` test helpers. Proven by
  `EnvironmentIsolationTest` (8 invariants) — incl. the load-bearing one: the
  org-level `withoutScope`/roll-up NEVER crosses an environment.
- [ ] Phase 2 — Environment entity + model, `environment_id` on organizations &
  all tenant-owned models, environment-scoped org closure.
- [ ] Phase 3 — Crypto: per-environment signing keys, issuer, JWKS, discovery.
- [ ] Phase 4 — Identity: environment-scoped users, email uniqueness, federated linking.
- [ ] Phase 5 — OAuth surface + environment resolution (host/API-key).
- [ ] Phase 6 — Signup lockdown (`signup.mode`).
- [ ] Phase 7 — Host: environment admin UI + entitlement/billing wiring per env.
