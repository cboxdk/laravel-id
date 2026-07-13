---
title: Start here — the mental model
description: Never built a central identity platform before? The one-page way to think about it, what to decide, and why — with links to the deep docs
weight: 0
---

# Start here — the mental model

If you've never run a central identity platform and the words *IdP, SSO, SCIM,
entitlements, tenancy* all blur together — read this page first. It's the
30,000-foot view: **what this is, the handful of things you actually decide, and
why.** Every section links to the deep doc when you need it.

## The one idea

> **Stop putting login, users, MFA, SSO and "who's allowed what" inside each app.
> Put them once in a central service, and let every app ask it.**

That central service is the **Identity Provider (IdP)**. Your apps become
**clients** of it. That's the whole shift.

```
        BEFORE                              AFTER
  ┌──────────┐ ┌──────────┐         ┌──────────┐ ┌──────────┐
  │ Product A│ │ Product B│         │ Product A│ │ Product B│   ← clients
  │ own login│ │ own login│         └────┬─────┘ └────┬─────┘     (no own login)
  │ own MFA  │ │ own MFA  │              └─────┬──────┘
  │ own users│ │ own users│              ┌─────▼──────┐
  └──────────┘ └──────────┘              │  Cbox ID   │   ← one IdP:
   two of everything,                    │   (IdP)    │     login, MFA, SSO,
   drifting apart                        └────────────┘     users, entitlements
```

## Two ways to run it — you don't have to build everything

This package (`cboxdk/laravel-id`) is the **framework**: the identity engine you
compose into your own Laravel app, wiring the UI, onboarding and admin console
yourself. That's the right choice if you want full control of the surface.

**If you'd rather not build the app layer at all, there's a full, deployable
application** — the **Cbox ID app** — built on this framework, with the admin
console, hosted login, onboarding and app-layer add-ons (like risk-scoring) already
implemented. Install it, configure it, run it. See its
[operator documentation](../../../../host/docs/index.md) (deployment, configuration,
operations, compliance).

The rest of this page is the mental model either way — the framework is what the app
is made of, so the concepts are identical.

## Why bother

You reach for this the moment any of these is true:

- **More than one app**, and you're tired of separate logins/user tables that drift.
- **Enterprise customers** asking for **SSO** ("log in with our Okta/Entra") and
  **SCIM** ("auto-provision our staff, and cut them off the day they leave").
- **Security must be provable** — MFA, passkeys, session revocation, an audit trail
  you can hand an auditor — and re-implementing that per app is how holes appear.
- **"What plan is this customer on"** needs to mean the same thing everywhere.

If you have exactly one small app and no enterprise buyers, you may not need this
yet. Everyone else eventually does.

## The five things you actually decide

Don't try to hold the whole system in your head. There are only five real
decisions; each is **one integration point**, not a rewrite.

### 1. Who are your users, and where do they live?

Cbox ID **never forces its own `users` table**. It refers to a person by an
opaque id through one contract (`Subjects`). Greenfield? Use the built-in store.
Already have users (even in Passport)? Bind your table and you're done.
→ [Integrating an existing app](../cookbook/integrating-existing-apps.md)

### 2. How do apps log in against it?

Over **OpenID Connect (OIDC)** — the standard "log in with…" protocol. Each app is
an OIDC client pointed at Cbox ID's discovery URL. One sign-in, one session, the
same canonical `sub` everywhere. → [Standards](../security/standards.md),
[Quickstart](../quickstart.md)

### 3. What's a "customer" — your tenancy model?

Cbox ID ships **Organizations + memberships** (users belong to orgs, with roles),
isolated **deny-by-default**. Adopt it, or bridge it to a tenant model you already
have. → [Integrating an existing app](../cookbook/integrating-existing-apps.md#4-unifying-tenancy)

### 4. Who's allowed what — and what did they pay for?

Two layers, kept separate on purpose:
- **Roles/permissions (RBAC/ReBAC):** what a member can *do*.
- **Entitlements:** what their *plan* includes — pushed from **your** billing, so
  every product enforces the same thing. → [Entitlements & billing](../core-concepts/entitlements-and-billing.md)

### 5. What do enterprise buyers need — SSO & SCIM?

- **SSO:** their employees log in with *their* IdP (Okta, Entra, Google).
- **SCIM:** their IT system provisions/deprovisions users into yours automatically.
Both are per-organization connections. → [Cookbook](../cookbook/index.md), [Standards](../security/standards.md)

## How to approach it (the order that works)

1. **Stand it up.** `php artisan cbox-id:install` bootstraps keys, config and
   migrations; `cbox-id:doctor` tells you what's healthy in plain language.
2. **Point it at your users** (decision #1). Nothing else works until "who is this
   person" is answered.
3. **Make one app log in through it** (decision #2). Prove the loop end-to-end with
   a single client before touching the rest.
4. **Add the second app** — now you have real Single Sign-On, and the payoff shows up.
5. **Layer in what your customers ask for** — tenancy, entitlements, SSO, SCIM —
   one at a time, each on its own. Don't do all five on day one.

## The principles behind the design (so nothing surprises you later)

- **Security is the product, not a feature.** Deny-by-default tenancy, a
  tamper-evident audit trail, alg-pinned tokens, key rotation. → [Security](../security/index.md),
  [Threat model](../security/threat-model.md)
- **Everything is a contract you can swap.** Users, validators, stores, policies —
  nothing is welded shut. → [Extending](../extension-points/index.md)
- **It's not the system of record for things it shouldn't own.** Not your users
  (your table is), not your money (your billing is) — it stores identity and the
  *decisions*, with provenance.
- **Standards over bespoke.** OIDC, SCIM, SAML, the relevant RFCs — so any client,
  in any language, integrates without custom glue. → [Standards](../security/standards.md)
- **Compliance is designed in, not bolted on.** The controls map to SOC 2, ISO
  27001, NIS2, GDPR, HIPAA, PCI-DSS. → [Compliance mapping](../security/compliance.md)

## Where to go next

- Ready to build → [Installation](installation.md) then
  [Quickstart](../quickstart.md).
- Already have an app → [Integrating an existing app](../cookbook/integrating-existing-apps.md).
- Want the shape of the system → [Architecture & patterns](../core-concepts/architecture.md).
