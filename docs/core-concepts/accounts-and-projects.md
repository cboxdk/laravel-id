---
title: Accounts, projects & the platform plane
description: The self-serve hierarchy above environments — one login, many independently-billed IdP products
weight: 2
---

# Accounts, projects & the platform plane

Above the tenancy boundary sits the **platform plane** — the self-serve hierarchy a
customer signs up into. It is one-directional:

```
Account  →  Project  →  Environment  →  Organization  →  Subject
```

- **Account** — the login/identity umbrella and the billing *customer*. It owns the
  **account members** (the humans who sign in at the platform root), payment methods,
  and account-wide settings. An account is *not* environment-scoped — it sits above
  the boundary, like operators.
- **Project** — one IdP **product**. This is the **billing anchor**: the plan, the
  environment allowance (`environment_limit`), and (with GA) the subscription live
  here. One account can own several projects, each **billed independently** — so a
  customer runs "Product 1" and "Product 2" from one login without a second email.
  Billing is anchored on the **project**, not the account, so one customer's two
  products are separately metered and separately invoiced.
- **Environment** — a project's isolated stage (production, sandbox). Each has its own
  keys, users, connections and sign-in, routed by host. See
  [Environments & the isolation model](environments.md).
- **Organization → Subject** — the end-user tenancy *inside* an environment.

## Why the project layer exists

Without it, an account could only create **environments** — the deploy stages of a
*single* IdP. Two products needing separate billing would force two accounts (two
emails). The project layer makes billing and environment allowance a **per-product**
concern while keeping a single login.

## Provisioning

`AccountProvisioner::provision(AccountBlueprint)` creates, in one transaction: the
account, its first member (the owner), a first **Default project**, and that project's
first **environment** — born empty of tenants (the account plane never seeds the
end-user plane). `addProject()` stands up further independently-billed products;
`addEnvironment(Project)` adds a stage and is gated on **that project's**
`environment_limit` (`EnvironmentLimitReached` is keyed on the project). A project's
first environment routes off the bare project slug; additional stages append their
name (`product`, `product-staging`).

## Billing lives on the project

The plan/allowance and subscription anchor on the **Project**, not the account. The
account's own `environment_limit` column is retained only as the **seed** the first
project inherits at provision time — it does **not** gate anything, and
`Accounts::remainingEnvironments()` is deprecated (it misreports capacity for a
multi-project account). Gate on `Projects::remainingEnvironments($project)`.

> **Two different "billing" concepts.** This page's project `environment_limit` is the
> *account/plan's environment allowance* on the platform plane. That is distinct from
> the **org-scoped entitlements** in [Entitlements & billing](entitlements-and-billing.md),
> which gate what an individual *tenant* may do inside an environment. Different layers,
> different owners.

## An account is an organization

`accounts.organization_id` has always said it: an account **is** an organization in the
platform-root environment, with members and a payment method bolted on. So an
organization can own IdP products directly, and `projects.organization_id` records that
link rather than inferring it through the account plane every time:

```php
$organization->projects;      // HasMany<Project>
$organization->environments;  // HasManyThrough<Environment, Project>

app(OrganizationProjects::class)->forOrganization($organizationId);
app(OrganizationProjects::class)->ownedByOrganization($projectId, $organizationId);
```

The column is stamped automatically on every project create (on the model, so a host
calling `Project::create()` directly gets it too) and backfilled for existing accounts.
`(organization_id, slug)` is unique, mirroring the `(account_id, slug)` key beside it.

**Nothing on the account side changes.** `Account::projects()`, `Projects::forAccount()`
and the provisioner answer exactly what they did; both sides report the same ownership,
and a consumer that never looks at the new column sees no difference.

### What crosses which scope

`Organization` is environment-owned; `Project` and `Environment` are not — a project
*owns* environments, and an environment *is* the boundary, so neither can live inside
one. Both relations therefore cross **out** of the environment scope. What makes that
safe is the **parent**, not the child: an `$organization` instance is only obtainable
from inside its own environment (the scope is deny-by-default and refuses it even by
primary key from anywhere else), and the child query is keyed on that organization's
id. Reaching another customer's projects would first mean reaching their organization.
It is the same shape, and the same argument, as `Account::projects()`.

`Organization::environments()` is deliberately a *through*-relation rather than a
denormalized `environments.organization_id`. Environments already nest under a project,
so the fact exists once; a second column would have to be written by every creation
path and would drift the first time one forgot.

### What has *not* moved yet

`projects.account_id` is still **NOT NULL**. An organization can be *read* as the owner
today; owning a project with no account behind it at all needs that column to become
nullable, as `environments.account_id` already is. That is the subtractive step, and it
is deliberately separate: this one is additive only.

### The environment allowance stays where it is

`Account::$environment_limit` is **not** copied to organizations. The enforced limit
lives on the **project** — `AccountProvisioner::addEnvironment()` gates on
`Projects::remainingEnvironments($project)` and throws `EnvironmentLimitReached` keyed
on the project. The account column is only the seed the first project inherits at
provision time, and that seed already arrives on `AccountBlueprint::$environmentLimit`;
the column is a remnant of the plan anchor's move to the project. A third copy on the
organization would add a number that can disagree with the one actually enforced, which
is the failure mode the move to the project was meant to end. Allowance is a
plan/entitlement concern, and it belongs to the thing that is billed.

## Single-tenant / self-hosted is untouched

The project layer is a **SaaS-only (Tier-2, multi-tenant) concept**. Like `account_id`,
`environments.project_id` is **nullable**, and a null is the sentinel for a
platform-owned environment — the self-hosted deployment's one forced IdP, on a single
domain, with no account and no project. Single-tenant never populates the layer, and
subdomain routing / the account plane only engage when `base_domains` is configured.

## Migrating existing accounts

The `add_project_id_to_environments` migration backfills a **Default** project per
existing account (inheriting the account's `environment_limit`) and repoints that
account's environments to it, so no multi-tenant account loses access. The backfill is
idempotent — an account that already has a project is skipped.
