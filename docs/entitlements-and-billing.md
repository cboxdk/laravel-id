---
title: Entitlements & billing
description: How each product keeps its own billing engine, yet pushes entitlements back to Cbox ID so every product enforces the same plan
weight: 7
---

# Entitlements & billing

## TL;DR

- **Keep your billing where it is.** Stripe, Cashier, Paddle, an invoicing team,
  a homegrown table — Cbox ID does **not** replace it and never touches money.
- **Billing is a source of truth; Cbox ID stores a *projection* of it.** When a
  subscription changes, your app translates "what did they buy" into
  **entitlements** (`plan=pro`, `seats.limit=50`, `feature.sso=enabled`) and
  **pushes** them to Cbox ID.
- **Every product then reads the same answer** — from the token (a claim) or a
  live check — instead of each product re-implementing "is this org on Pro?".
- **One call does it safely:** `reconcile()` sets the full desired state and
  revokes anything no longer bought — so a dropped webhook can't leave an org
  entitled to something they cancelled.

```
  Stripe / Cashier / Paddle / your billing
        │  (subscription.updated webhook)
        ▼
  YOUR app: map plan → entitlements          ← you own this mapping
        │  push (EntitlementWriter / SDK)
        ▼
  Cbox ID: versioned projection ──► token claims  ─┐
                                └─► decision API ───┤──►  every product enforces
                                                    ┘     the same entitlement
```

Money and invoices stay in your billing engine. Cbox ID only ever holds the
*consequence* — "this org is allowed X" — and hands that to every product.

## Why this split

Each product usually has its **own** billing (different Stripe account, different
plans, sometimes no Stripe at all). That's fine and expected — billing is not the
thing you want to centralize. What you *do* want centralized is the **decision**:

- Without it, every product re-derives entitlements from raw billing data, and
  they drift. Product A thinks the org is on Pro; Product B still sees Free.
- With it, billing pushes once, and "Pro" means the same thing everywhere —
  including in tokens, so a resource server can enforce it without a DB lookup.

Cbox ID is deliberately **not** the system of record. It records *where each
value came from* (`EntitlementSource::Billing | Manual | System`) and *what
version* it is, so provenance is always auditable.

## The model

An entitlement is a small key → value bag with an enforcement mode:

| Piece | What it is | Example |
|---|---|---|
| **key** | stable identifier | `plan`, `seats`, `feature.sso` |
| **value** | arbitrary JSON | `{"tier":"pro"}`, `{"limit":50}`, `{"enabled":true}` |
| **source** | who's authoritative | `Billing` (usually), `Manual`, `System` |
| **mode** | how it's enforced | `Claims` or `DecisionApi` (below) |

Every write is **versioned, appended to history, emitted as an event
(`entitlement.updated` / `entitlement.revoked`) and written to the audit log** —
so you can answer "when did this org get SSO, and from what?" months later.

## Pushing from billing

The push side is one contract — `EntitlementWriter`. If your billing lives *in*
the Cbox ID host, resolve it directly; if billing lives in a **separate product**,
call the equivalent API endpoint over the SDK (products don't embed the package —
they call the running instance). The shape is identical either way.

### The safe default: `reconcile()`

On any billing event, compute the org's **entire** desired entitlement set and
reconcile. This upserts everything present and revokes anything absent — the one
call that survives dropped or out-of-order webhooks:

```php
use Cbox\Id\Kernel\Authorization\Contracts\EntitlementWriter;
use Cbox\Id\Kernel\Authorization\Enums\EnforcementMode;
use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementInput;

// In your Stripe/Cashier webhook handler, after you know the new subscription state:
app(EntitlementWriter::class)->reconcile($organizationId, [
    new EntitlementInput('plan',        ['tier' => $plan]),                             // Claims (default)
    new EntitlementInput('seats',       ['limit' => $seats], EnforcementMode::DecisionApi),
    new EntitlementInput('feature.sso', ['enabled' => $plan === 'enterprise']),
], EntitlementSource::Billing);
```

Map your plans to entitlements in **one place** (a `PlanCatalog` in your app) so
"what does Pro include" is a single, testable function. Cbox ID intentionally
does not model plans — it stores the resolved entitlements they grant.

### Incremental writes

For a single, targeted change (a manual grant, a one-off add-on) use `set()` /
`revoke()`. Pass a `sourceRef` (the Stripe subscription/event id) so the history
row points back to the billing record it came from:

```php
$writer->set($organizationId,
    new EntitlementInput('feature.audit_export', ['enabled' => true]),
    EntitlementSource::Billing,
    sourceRef: $stripeSubscriptionId,
);

$writer->revoke($organizationId, 'feature.audit_export', EntitlementSource::Billing);
```

> **Prefer `reconcile()` for webhook-driven billing.** `set`/`revoke` are for
> deltas you're certain about; `reconcile` is self-healing against drift.

## Enforcing entitlements — the hot path

Entitlements are **not baked into the access token**. That is deliberate: a plan
downgrade, a cancellation or an abuse kill-switch must take effect *now*, not after
a token expires. Instead they are resolved **live** against the decision plane, so
the token stays a thin identity bearer and the change is visible on the very next
request — no refresh, no session disruption.

Two ways to read them, both live:

**1. In-process (a product that embeds the framework):** call the reader / PDP
directly. Reads are served from a per-org, version-invalidated cache, so a check on
every request is cheap; a write bumps the version and the next read is instantly
fresh.

```php
use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;

$reader = app(EntitlementReader::class);              // cache-backed, instant on change
$isPro  = $reader->get($orgId, 'plan')?->string('tier') === 'pro';
$seats  = $reader->get($orgId, 'seats')?->int('limit') ?? 0;
```

**2. Over HTTP (an external resource server):** `POST /oauth/decisions` with the
caller's access token asks for permissions *and* entitlements in one round trip —
the same decision plane that answers "may this subject do X?" also answers "does
the org have entitlement Z?".

```http
POST /oauth/decisions              Authorization: Bearer <access token>
{ "permissions": [{"relation": "manage", "resource": "ticket:42"}],
  "entitlements": ["plan", "seats"] }

→ { "subject": {...}, "organization": "org_x",
    "permissions": [{"relation":"manage","resource":"ticket:42","allowed":true}],
    "entitlements": {"plan": {"value":{"tier":"pro"},"version":3}, "seats": null} }
```

### The hybrid: live by default, coarse in the token by choice

`EnforcementMode` picks how each entitlement propagates — and the platform, like
WorkOS, supports both:

| Mode | Propagation | Where it lives | Use for |
|---|---|---|---|
| `DecisionApi` **(default)** | **instant** | resolved live (reader / `/oauth/decisions`) | anything you must switch off now — seats, kill-switches, most billing |
| `Claims` | bounded by access-token TTL (~15 min), on the next silent refresh | **embedded in the token** as the `ent` claim | coarse, slow-changing gates — `plan`, `feature.sso` — where you want a stateless check with zero round trip |

A token issued for an org carries its `Claims`-mode entitlements plus an `ent_ver`
(the highest version among them, so a resource server can spot a stale token and
re-check live if it cares):

```json
{ "sub": "user_1", "org": "org_x",
  "ent": { "plan": {"tier": "pro"}, "feature.sso": {"enabled": true} },
  "ent_ver": 7 }
```

`DecisionApi`-mode entitlements are **never** baked into a token — they stay live.
Set `CBOX_ID_EMBED_ENTITLEMENTS=false` to keep `ent` out of tokens entirely.

**Opinion:** default to `DecisionApi` (instant, no staleness surprise) and reach for
`Claims` deliberately, only for the handful of gates where a stateless per-request
check matters more than instant revocation. That is the safe half of the hybrid.

## Reacting to changes

Every write emits a domain event, so other systems stay in sync without polling:

```php
// entitlement.updated / entitlement.revoked  — payload carries key + version.
Event::listen('entitlement.updated', function ($e) {
    // bust an edge cache, notify a product, trigger provisioning, …
});
```

Deprovisioning (SCIM, membership removal) and entitlement revocation both flow
through the same audited pipeline — see [Security](security.md).

## Putting it together

1. **Billing stays yours.** Keep Stripe/Cashier/whatever, per product.
2. **On every billing change, `reconcile()`** the org's full entitlement set with
   `EntitlementSource::Billing`.
3. **Choose a mode per key** — `Claims` for coarse, `DecisionApi` for instant-revoke.
4. **Products read entitlements from the token** (or the decision API), never from
   raw billing data — so every product enforces the same plan.
5. **Provenance is free** — version, source and history are recorded on every write.

## Where to go next

- [Cookbook](cookbook.md) — the reconcile snippet in context, plus RBAC and SSO.
- [Integrating an existing app](integrating-existing-apps.md) — adopt over an app
  that already has users and billing.
- [Security](security.md) — how entitlement writes are tenant-scoped and audited.
- [Standards](standards.md) — the token/claims and decision surfaces products call.
