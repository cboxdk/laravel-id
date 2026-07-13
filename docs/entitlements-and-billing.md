---
title: Entitlements & billing
description: Entitlements are capability gates — what an org may do — fed by your billing engine, never billing state itself
weight: 7
---

# Entitlements & billing

## TL;DR

- **Entitlements are capability gates, not billing facts.** Cbox ID holds *"this
  org may do X"* — `feature.sso: on`, `seats.limit: 50`, `api.export: on`,
  `usage.over_quota: false`. It never holds the plan name, the price, or a usage
  count. Those are billing's, and they stay there.
- **Billing is the source of truth; it translates plan + usage into gates and
  pushes them in.** Your billing engine knows *"Pro → grant [feature.sso,
  seats.limit=50]"*; Cbox ID only ever sees the resulting capabilities.
- **Every product reads the same gate** — live from the decision plane, or from a
  token claim — instead of re-deriving "what can this org do" from raw billing data.
- **One call keeps it honest:** `reconcile()` sets the full desired gate set and
  revokes anything no longer granted, so a dropped webhook can't leave a capability
  switched on after it was cancelled.

```
  Stripe / Cashier / Lago / your billing engine        ← owns plans, prices, usage
        │  translate plan + usage → capability gates
        ▼
  EntitlementWriter.reconcile(org, [gates])            ← you own this mapping
        ▼
  Cbox ID: versioned capability projection ──► /oauth/decisions (live)  ─┐
                                          └──► `ent` token claim (coarse) ┤──► products gate
                                                                         ┘
```

Cbox ID never touches money and never counts usage. It holds the **consequence** —
"this org is allowed X" — as pure authorization, the same shape as roles and
permissions. That is why entitlements live in the [decision plane](authorization.md)
next to permissions: both are just *capability grants*.

## Why entitlements are gates, not billing

Keeping the plan/price/usage out of Cbox ID is deliberate:

- **One clean boundary.** Billing owns everything that produces a gate (which plan,
  how much used, what was paid). Cbox ID owns only the gate. Change your pricing,
  switch Stripe for Lago, add a promo — none of it touches the authorization layer,
  because the layer never knew "Pro" or "$29" in the first place.
- **No drift.** Every product enforces the *same* gate rather than each
  re-implementing "is this org on Pro?" against raw billing data.
- **Provenance for free.** Each gate records where it came from
  (`EntitlementSource::Billing | Manual | System`) and its version — so you can
  answer "when did this org get SSO, and from what?" months later.

## The model

An entitlement is a capability gate: a stable `key` → a small `value` bag.

| Piece | What it is | Example |
|---|---|---|
| **key** | the capability | `feature.sso`, `seats`, `api.export`, `usage.over_quota` |
| **value** | the gate's shape | `{"enabled":true}`, `{"limit":50}`, `{"value":false}` |
| **source** | who granted it | `Billing` (usually), `Manual`, `System` |
| **mode** | how it propagates | `DecisionApi` (live, default) or `Claims` (in the token) |

Note there is no `plan` gate — a plan is a billing concept. What the plan *grants*
is a set of capability gates, and those are what Cbox ID holds.

Every write is **versioned, appended to history, emitted as an event
(`entitlement.updated` / `entitlement.revoked`) and audited**.

## Pushing gates from billing

The push side is one contract — `EntitlementWriter`. Billing maps plan + usage to
gates in **one place** (a `CapabilityCatalog` in your billing code — *"Pro grants
these gates"*) and reconciles them.

### The safe default: `reconcile()`

On any billing change, compute the org's **entire** desired gate set and reconcile.
It upserts what's present and revokes what's absent — the one call that survives
dropped or out-of-order webhooks:

```php
use Cbox\Id\Kernel\Authorization\Contracts\EntitlementWriter;
use Cbox\Id\Kernel\Authorization\Enums\EnforcementMode;
use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementInput;

// In billing, after the subscription/usage state is known, translate it to gates:
app(EntitlementWriter::class)->reconcile($organizationId, [
    new EntitlementInput('feature.sso',  ['enabled' => true]),                          // capability, from the plan
    new EntitlementInput('feature.export', ['enabled' => true]),
    new EntitlementInput('seats',        ['limit' => 50], EnforcementMode::DecisionApi), // a limit, checked live
    new EntitlementInput('usage.over_quota', ['value' => false]),                        // a usage-derived gate (below)
], EntitlementSource::Billing);
```

Cbox ID stores exactly these gates. It does not know they came from "Pro" — only
billing does.

### Incremental writes

For a single targeted change (a manual grant, a one-off add-on) use `set()` /
`revoke()`, with a `sourceRef` back to the billing record:

```php
$writer->set($organizationId,
    new EntitlementInput('feature.audit_export', ['enabled' => true]),
    EntitlementSource::Billing,
    sourceRef: $subscriptionId,
);

$writer->revoke($organizationId, 'feature.audit_export', EntitlementSource::Billing);
```

> **Prefer `reconcile()` for webhook-driven billing.** `set`/`revoke` are for
> deltas you're certain about; `reconcile` is self-healing against drift.

## Usage-based gates — where counting lives

Usage is billing's job, not Cbox ID's. There are two shapes, and neither puts a
counter in the authorization layer:

- **Coarse quota gates** (crossed the monthly limit): billing counts, and when the
  threshold flips it pushes a gate — `usage.over_quota: true`. Products read the
  gate; they never see the number. The [version-invalidated cache](authorization.md#freshness--why-its-instant)
  makes the flip visible on the next request.
- **Fine per-request enforcement** (rate limits, "is this the 10001st call"):
  enforced at the **billing/metering ingress** at request time — the place that
  owns the live counter — not in Cbox ID. The IdP never meters.

So Cbox ID always holds a *gate* (`over_quota: false`), never a *count*
(`used: 8000`). If you build a metering/billing package, the ledger and rating live
there; only the resulting gates are pushed here.

## Enforcing gates — the hot path

Gates are resolved **live** by default, so a downgrade or a kill-switch takes effect
on the very next request — no token refresh, no session disruption. See
[Authorization & the decision plane](authorization.md) for the full endpoint; in
short:

```php
use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;

$reader = app(EntitlementReader::class);                    // cache-backed, instant on change
$canUseSso = (bool) $reader->get($orgId, 'feature.sso')?->bool();
$seatLimit = $reader->get($orgId, 'seats')?->int('limit') ?? 0;
```

```http
POST /oauth/decisions              Authorization: Bearer <access token>
{ "permissions": [{"relation": "manage", "resource": "ticket:42"}],
  "entitlements": ["feature.sso", "seats"] }

→ { "organization": "org_x",
    "permissions": [{"relation":"manage","resource":"ticket:42","allowed":true}],
    "entitlements": {"feature.sso": {"value":{"enabled":true},"version":3}, "seats": null} }
```

### The hybrid: live by default, coarse in the token by choice

`EnforcementMode` picks how each gate propagates — and the platform, like WorkOS,
supports both:

| Mode | Propagation | Where it lives | Use for |
|---|---|---|---|
| `DecisionApi` **(default)** | **instant** | resolved live (reader / `/oauth/decisions`) | anything you must switch off now — seat limits, kill-switches, quota gates |
| `Claims` | bounded by access-token TTL (~15 min), on the next silent refresh | **embedded in the token** as the `ent` claim | coarse, slow-changing gates — `feature.sso` — where a stateless check with zero round trip matters more |

A token carries its `Claims`-mode gates plus an `ent_ver` (a staleness signal, so a
resource server can spot a stale token and re-check live if it cares):

```json
{ "sub": "user_1", "org": "org_x",
  "ent": { "feature.sso": {"enabled": true}, "feature.export": {"enabled": true} },
  "ent_ver": 7 }
```

`DecisionApi`-mode gates are **never** baked into a token. Set
`CBOX_ID_EMBED_ENTITLEMENTS=false` to keep `ent` out of tokens entirely.

**Opinion:** default to `DecisionApi` (instant, no staleness surprise) and reach for
`Claims` deliberately, only for the handful of gates where a stateless per-request
check beats instant revocation. That is the safe half of the hybrid.

## Reacting to changes

Every write emits a domain event, so other systems stay in sync without polling:

```php
// entitlement.updated / entitlement.revoked  — payload carries key + version.
Event::listen('entitlement.updated', function ($e) {
    // bust an edge cache, notify a product, trigger provisioning, …
});
```

## Putting it together

1. **Billing stays yours** and owns plans, prices and usage — Stripe, Cashier, Lago,
   whatever.
2. **Billing translates plan + usage into capability gates** and `reconcile()`s them
   with `EntitlementSource::Billing`. Cbox ID never sees the plan, price, or count.
3. **Choose a mode per gate** — `DecisionApi` (live, default) or `Claims` (in-token).
4. **Products enforce the gate**, live via the decision plane or from the token —
   never by re-deriving from raw billing data.
5. **Provenance is free** — version, source and history on every write.

## Where to go next

- [Authorization & the decision plane](authorization.md) — how gates and permissions are resolved live.
- [Cookbook](cookbook.md) — the reconcile snippet in context, plus RBAC and SSO.
- [Integrating an existing app](integrating-existing-apps.md) — adopt over an app that already has users and billing.
- [Security](security.md) — how entitlement writes are tenant-scoped and audited.
