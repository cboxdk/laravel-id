---
title: Environments & the isolation model
description: The hard identity boundary above organizations — staging/prod and white-label, WorkOS-style
weight: 2
---

# Environments & the isolation model

An **environment** is the platform's hard isolation boundary: its own user pool,
signing keys, issuer and organization tree. It is the layer *above* the
organization (tenant) — the same concept WorkOS calls an *Environment*, Auth0 a
*Tenant*, and Okta an *Org*. Use it to separate **staging from production**, or to
give a product / white-label reseller a fully isolated plane.

## The hierarchy

```
Environment   ── hard boundary: own users, signing keys, issuer, discovery, branding
├── Users            ── the user pool, shared within the environment
├── Organizations    ── a closure-tree of ANY depth (company → division → dept → team)
│   └── Memberships  ── user ↔ org node + role
└── Clients          ── your OAuth apps / products
```

The organization layer is an **arbitrary-depth tree** — closer to Active
Directory's nested OUs than to the usually-flat "Organizations" of other IdPs.
Delegated administration and role inheritance run down that tree, but always
**bounded by the environment**.

| This platform | Active Directory | WorkOS / Auth0 / Okta |
|---|---|---|
| **Environment** | Forest / Domain | Environment / Tenant / Org |
| **Organization** (closure-tree) | OU tree | Organizations |
| **User** (via Membership) | User in an OU | User |
| **Client** | app | Application |

## Two topologies — chosen by placement, not code

- **Shared identity across products.** Put several products in the **same**
  environment: a user signs up once and gets SSO across all of them, and a
  customer org's SSO connection serves every product in that environment.
- **Isolated per product / white-label.** Put a product (or reseller) in its
  **own** environment: separate user pool, keys, issuer and branding — a
  standalone "IdP in a box".

## Resolution — how a request finds its environment

Every API request resolves its environment from the **host** before anything
else runs (the `ResolveEnvironment` middleware, backed by an `EnvironmentResolver`):

1. an exact **custom-domain** match (`environments.domain`), else
2. the **leading DNS label** as an environment **slug** (`id.staging.acme.com` →
   the `staging` environment).

For a single-tenant / on-prem deployment, set `cbox-id.environments.default` to
your one environment key and every host resolves to it. In a multi-tenant
deployment, a host that maps to no environment is **refused** (404) rather than
served the wrong plane. Swap the bound `EnvironmentResolver` to resolve by API
key or header instead.

## Isolation guarantees — and how they're proven

The environment boundary is **deny-by-default and load-bearing**: a query with no
environment in context returns *nothing*, never another environment's rows. Each
guarantee below is proven by a dedicated test in the suite (`--group=isolation`);
if any ever passes while a leak exists, the platform's core promise is void.

| Guarantee | Proven by |
|---|---|
| The org-level escape hatch (`withoutScope`) and roll-up **never** cross an environment | `EnvironmentIsolationTest` |
| An organization (and its whole closure subtree) is invisible from another environment | `OrganizationEnvironmentTest` |
| A token signed in one environment **never verifies** in another (distinct keys/JWKS) | `CryptoEnvironmentIsolationTest` |
| The same email is a **distinct user** per environment; sessions never cross; a federated identity resolves only within its environment | `IdentityEnvironmentTest` |
| A client / connection / directory / opaque code is unusable from another environment | `OAuthEnvironmentTest` |
| A request's environment is resolved from its host; an unknown host is refused | `EnvironmentResolutionTest` |

Run them alone with:

```bash
vendor/bin/pest --group=isolation
```

## Making a model environment-owned

Any tenant-owned model that must be partitioned by environment implements
`EnvironmentOwned` and uses `BelongsToEnvironment` — it then auto-stamps
`environment_id` on create and is scoped on every read. It composes with
`BelongsToTenant`: environment is the hard outer wall, organization the inner,
roll-up-able one.

```php
final class Thing extends Model implements EnvironmentOwned, TenantOwned
{
    use BelongsToEnvironment;
    use BelongsToTenant;
}
```

In tests, act as an environment exactly like a tenant:

```php
uses(Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy::class);

$this->actingAsEnvironment('env_a');           // pin the hard boundary
$this->runAsEnvironment('env_b', fn () => ...); // scoped, then restored
```
