---
title: Architecture & Patterns
description: Kernels vs domain modules, dependency direction, contracts-first DI, dogfooding
weight: 3
---

# Architecture & Patterns

## Two layers

```
Kernel\{Tenancy, Crypto, Audit, Events, Authorization}   ← shared primitives
        ▲
Domain\{Organization, Identity, AccessControl,           ← features built on kernels
        Directory, Federation, Webhooks, AuditQuery}
        ▲
Your app / the hosted SaaS shell                          ← consumes the domain contracts
```

**Kernels** depend only on the framework and, in dependency order, each other (Audit signs
checkpoints with Crypto; Authorization emits via Events and records via Audit). They own no
business concepts.

**Domain modules** depend on kernels and on other modules' `Contracts/` only — never their
internals. A module's public surface is exactly its `Contracts/` namespace.

## Contracts-first, resolved from the container

Every capability is an interface bound to an implementation in a module service provider:

```php
$this->app->singleton(UserDirectory::class, DatabaseUserDirectory::class);
```

So you always depend on the contract, and you can swap the implementation, decorate it, or
mock it without touching callers. See [Extending](../extension-points/_index.md).

```php
public function __construct(private readonly UserDirectory $users) {}
```

## Deny-by-default everywhere

- **Tenancy**: a query on a tenant-owned model with no tenant in context returns *zero* rows,
  never all of them. A missing tenant can't leak another tenant's data.
- **Authorization**: the PDP allows only on an explicit relationship grant; anything else denies.
- **Crypto**: JWT verification takes an explicit algorithm allow-list; `alg=none` and RS↔HS
  confusion are impossible.

## Value objects and enums

Inputs and results are immutable value objects (`NewOrganization`, `FederatedPrincipal`,
`EntitlementInput`, `Decision`, …) and every status/type is an enum. There are no array-shaped
"config bags" flowing through business logic.

## Dogfooding

Modules use the kernels the same way you would, which keeps the primitives honest:

- `Organization` **is** a `Tenant`; membership writes run inside `TenantContext::runAs()`.
- `Directory` deprovision calls `SessionManager::revokeAllForUser()` — SCIM offboarding kills
  sessions instantly.
- `AccessControl` resolves permissions across `OrganizationHierarchy::ancestors()`, so roles
  roll down from a reseller to the customers it manages.
- `Webhooks` listens for the Events kernel's `EventDelivered` and seals endpoint secrets with
  the Crypto `SecretBox`.

## Hierarchy without weakening isolation

The reseller/parent tree is a **closure table** (`OrganizationHierarchy`), never a loosening of
the tenant scope. Cross-org reach is an explicit, authorized elevation:

- **Roll-down** (a parent's role/entitlement applies to descendants) — resolved via the closure.
- **Roll-up** (a parent reporting over descendants) — `TenantContext::scopedTo([...keys])`, a
  bounded, authorized read set; deny-by-default on an empty set.

The isolation kernel itself stays strict and unchanged.
