---
title: Accounts, projects & the platform plane
description: The self-serve hierarchy above environments — one login, many independently-billed IdP products (the Clerk "Applications" model)
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
  This is exactly the **Clerk "Application"** (and Auth0 "Tenant") model. (WorkOS,
  by contrast, bills at the account level — so this goes a layer beyond it.)
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
