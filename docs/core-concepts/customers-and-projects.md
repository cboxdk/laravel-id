---
title: Customers, projects & the platform plane
description: The self-serve hierarchy above environments — one login, many independently-billed IdP products
weight: 2
---

# Customers, projects & the platform plane

Above the tenancy boundary sits the **platform plane** — the self-serve hierarchy a
customer signs up into. It is one-directional:

```
Organization  →  Project  →  Environment  →  Organization  →  Subject
   (customer)                                  (that tenant's own)
```

**A CUSTOMER IS AN ORGANIZATION.** There used to be an `Account` row above the
organization, carrying the same name and the same status, with its own members and its own
role vocabulary — two rows for one customer, and therefore two answers to "who may act for
them". They kept disagreeing. The account row is gone rather than reconciled: a customer is
an organization living in the **platform root**, and their people are ordinary subjects who
hold a membership of it.

The word *organization* therefore does two jobs, and the distinction is worth holding onto:
in the root it names a **customer of this platform**; inside a tenant's own environment it
names one of **that customer's end-user organizations**. What tells them apart is that a
customer owns **projects**.

- **Organization (the customer)** — the billing customer and the login umbrella. It owns
  the **memberships** that place people on the management plane, and it lives in the
  **platform root** environment. Its people are ordinary subjects: one identity, one
  credential, one session.
- **Project** — one IdP **product**. This is the **billing anchor**: the plan, the
  environment allowance (`environment_limit`) and the subscription live here. One customer
  can own several projects, each **billed independently** — so they run "Product 1" and
  "Product 2" from one login without a second email.
- **Environment** — a project's isolated stage (production, sandbox). Each has its own
  keys, users, connections and sign-in, routed by host. See
  [Environments & the isolation model](environments.md).
- **Organization → Subject** — the end-user tenancy *inside* an environment. Same word,
  different altitude; see the note above.

## Why the project layer exists

Without it, a customer could only create **environments** — the deploy stages of a *single*
IdP. Two products needing separate billing would force two customers (two emails). The
project layer makes billing and environment allowance a **per-product** concern while
keeping a single login.

## Provisioning

`TenantProvisioner::provision(TenantBlueprint)` creates, in one transaction: the
organization, the owner's **subject**, that owner's **membership** (role `Owner`), a first
project named after them, and that project's first **environment** — born empty of tenants,
because the management plane never seeds the end-user plane.

`addProject()` stands up further independently-billed products; `addEnvironment(Project)`
adds a stage and is gated on **that project's** `environment_limit`
(`EnvironmentLimitReached` is keyed on the project). Both refuse for a suspended customer
(`OrganizationSuspended`) — an off-switch that only stops reads is not one. A project's
first environment routes off the bare project slug; additional stages append their name
(`product`, `product-staging`).

An owner who **already holds a Cbox ID** is attached rather than re-created, and the
blueprint's password is only applied when the subject is being created. Provisioning is not
a password reset: letting it be one would hand anyone who can provision the credential of
anyone whose address they can guess.

## Billing lives on the project

The plan/allowance and subscription anchor on the **Project**. There is no
organization-level allowance to disagree with it — one customer can own several
independently-billed products, so a single number above them could only ever misreport.
Gate on `Projects::remainingEnvironments($project)`.

> **Two different "billing" concepts.** This page's project `environment_limit` is the
> *plan's environment allowance* on the platform plane. That is distinct from the
> **org-scoped entitlements** in [Entitlements & billing](entitlements-and-billing.md),
> which gate what an individual *tenant* may do inside an environment. Different layers,
> different owners.

## Everything a customer's people do is a membership

There is no separate member table, no second role vocabulary and no second password column.

- **Who they are** — a `Subject` in the platform root, the same row shape a tenant's own
  end user occupies.
- **What they may do here** — a `Membership` of the customer organization, carrying a
  `MembershipRole`. The same person can own one organization and be a viewer in another,
  and neither fact belongs on the identity.
- **Which environments they reach** — the membership's environment grants
  (`Memberships::accessibleEnvironmentIds($organizationId, $subjectId)`).

Both tables are **environment-owned**, and a customer's rows live in the platform root. Any
read of them from a tenant host must say so explicitly (`PlatformRoot::run()`); the
deny-by-default scope answers with an empty set otherwise, which reads exactly like "this
person has no access".

`memberships` is **tenant-owned as well**, and that scope is deny-by-default too — so a bare
`Membership::query()` with no tenant in context matches nothing. Go through the
`Memberships` contract, which runs each call inside the organization's own tenant scope.

## Single-tenant / self-hosted is untouched

The project layer is a **SaaS-only (Tier-2, multi-tenant) concept**.
`environments.project_id` is **nullable**, and a null is the sentinel for a platform-owned
environment — the self-hosted deployment's one forced IdP, on a single domain, owned by
nobody. That sentinel does real work: it is how the platform root itself is recognised, and
`PlatformRoot` refuses a configured root that a customer owns precisely by asking whether it
has a project. Single-tenant never populates the layer, and subdomain routing and the
management plane only engage when `base_domains` is configured.

## There is no migration path

Production is rebuilt with `migrate:fresh`. The account plane's tables, and every backfill
that used to carry rows across from them, were deleted rather than migrated — deliberately,
because reconciling two answers to "who is this customer" was the problem, not the schema.
