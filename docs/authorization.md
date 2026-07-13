---
title: Authorization & the decision plane
description: How Cbox ID answers "may this subject do X?" and "does this org have entitlement Z?" — live, instant, and optionally in the token
weight: 8
---

# Authorization & the decision plane

Cbox ID is not just an authenticator — it is the **authorization decision plane**
for everything built on it. There is one place that answers *"may this subject do
X on Y?"* (permissions) and *"does this org have entitlement Z?"* (billing-fed
entitlements), and enforcement points call it rather than re-implementing logic.
The model is **deny-by-default** and lineage-wise sits with Google Zanzibar /
OpenFGA / SpiceDB: fast-changing authorization is resolved **live**, not frozen
into a long-lived token.

```
                      ┌──────────────────────────┐
  "can alice          │   PolicyDecisionPoint    │  ← the single decision point
   manage ticket:42?" │   ├─ RelationshipStore   │    (deny-by-default)
  ──────────────────► │   │   (ReBAC / roles)    │
  "does org_x have    │   └─ EntitlementReader   │  ← cache-backed, version-fresh
   entitlement pro?"  │       (billing-fed)      │
  ──────────────────► └──────────────────────────┘
```

## Two ways to ask

### 1. In-process — `PolicyDecisionPoint`

An app that embeds the framework calls the PDP directly. Deny-by-default: the only
source of "allow" is an explicit relationship grant.

```php
use Cbox\Id\Kernel\Authorization\Contracts\PolicyDecisionPoint;
use Cbox\Id\Kernel\Authorization\ValueObjects\{Subject, ResourceRef};

$pdp = app(PolicyDecisionPoint::class);

$pdp->can('org_x', Subject::user('alice'), 'manage', ResourceRef::of('ticket', '42')); // bool
$pdp->entitlement('org_x', 'feature.sso')?->bool();                                     // capability gate
```

Relationships are stored as ReBAC tuples (`RelationshipStore`), supporting grants
through group membership (e.g. `doc:1#viewer@group:eng#member`). Entitlement reads
are served from a per-org, version-invalidated cache, so a check on every request
is cheap and a change is visible on the next read.

### 2. Over HTTP — `POST /oauth/decisions`

An external resource server presents the caller's access token and gets permissions
**and** entitlements in one round trip. This is the hot path — resolved live, so a
revoked role or a flipped capability gate takes effect on the very next call.

> Entitlements here are **capability gates** — *"this org may do X"* — not billing
> state. Cbox ID never holds a plan name, a price, or a usage count; billing
> translates those into gates and pushes them in. See
> [Entitlements & billing](entitlements-and-billing.md).

```http
POST /oauth/decisions
Authorization: Bearer <access token>

{ "permissions": [ {"relation": "manage", "resource": "ticket:42"} ],
  "entitlements": [ "feature.sso", "seats" ] }
```

```json
{ "subject": {"type": "user", "id": "alice"},
  "organization": "org_x",
  "permissions": [ {"relation": "manage", "resource": "ticket:42", "allowed": true} ],
  "entitlements": { "feature.sso": {"value": {"enabled": true}, "version": 3}, "seats": null } }
```

The subject and org come from introspecting the presented token (deny-by-default if
it is inactive or carries no org). A `client_credentials` token resolves to a
`service` subject; a user token to a `user` subject.

## Freshness — why it's instant

Entitlement reads sit behind a version-tagged cache: the read key embeds the org's
current version, and every write bumps that version, so the next read routes to a
fresh key — atomic, correct across cache nodes, no explicit flush. A billing
downgrade is therefore visible on the next decision call with no token refresh and
no session disruption. Permissions are read live from the relationship store, so
they are always current.

## The hybrid — coarse entitlements in the token

Like WorkOS (which splits its live FGA check from RBAC/entitlement *claims* in the
session), Cbox ID lets you embed the **coarse, slow-changing** entitlements in the
access token for a stateless per-request check, while keeping the instant-critical
ones live. This is the per-entitlement `EnforcementMode`:

- `DecisionApi` **(default)** — resolved live; instant on change; never in a token.
- `Claims` — embedded in the token as the `ent` claim (with `ent_ver` for staleness
  detection); propagates on the next silent refresh (~15-min access-token TTL).

See [Entitlements & billing](entitlements-and-billing.md#the-hybrid-live-by-default-coarse-in-the-token-by-choice)
for the token shape and the `CBOX_ID_EMBED_ENTITLEMENTS` switch.

**Rule of thumb:** default everything to live (instant, no staleness surprise);
reach for `Claims` deliberately for the handful of gates where a zero-round-trip
check matters more than instant revocation.

## Roadmap

For push-based realtime — the IdP proactively telling resource servers to
re-evaluate the moment a role, entitlement or session changes, instead of them
polling — the next step is **CAEP / Shared Signals** (RFC 8417 Security Event
Tokens) layered on the `entitlement.updated` / session-revocation events the
platform already emits.

## Where to go next

- [Entitlements & billing](entitlements-and-billing.md) — the billing side and the hybrid in detail.
- [Security](security.md) — tenant isolation and the invariants underneath.
- [Extending](extending.md) — swap the relationship store or entitlement source.
