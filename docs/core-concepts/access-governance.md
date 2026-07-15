---
title: Access governance
description: Identity Governance & Administration — access-certification campaigns and Segregation-of-Duties policies over your RBAC roles and memberships
weight: 13
---

# Access governance

The governance module (`Cbox\Id\Governance\`) is the Identity Governance &
Administration (IGA) layer: it governs *who holds what access over time*, on top of
the RBAC roles and organization memberships the platform already tracks. Two
capabilities:

- **Access certification campaigns** — periodic access reviews. Snapshot the access
  grants in an organization, put each in front of a reviewer to **certify** or
  **revoke**, and on close **apply** every revoke against the real access contracts.
- **Segregation of Duties (SoD)** — policies that forbid toxic role combinations,
  with a pre-grant gate and a detector for conflicts that already exist.

It is a server-side primitive (contracts you resolve and call), not a UI.

## Access certification campaigns

```php
use Cbox\Id\Governance\Contracts\AccessReviews;

$reviews = app(AccessReviews::class);

// Open a campaign — snapshots every DIRECT role assignment and membership in the org.
$campaign = $reviews->open('acme', 'Q3 access review', dueAt: now()->addWeek());

foreach ($reviews->itemsFor($campaign->id) as $item) {
    // A reviewer decides on each grant ($item->subject_id holds $item->access_ref).
    $stillNeeded
        ? $reviews->certify($item->id, reviewerId: $manager->id)
        : $reviews->revoke($item->id, reviewerId: $manager->id, note: 'left the team');
}

// Close applies every revoke (Roles::unassign / Memberships::remove) and marks the
// campaign closed. Items still un-reviewed follow the campaign's PendingPolicy.
$reviews->close($campaign->id);
```

- **Decisions are reversible until close.** `revoke()` only records intent; the actual
  removal happens at `close()`, so a reviewer can change their mind while the campaign
  is open.
- **Pending items are safe-by-default.** Anything left un-reviewed at close takes the
  campaign's `PendingPolicy` — the default is **Revoke** (access no one vouched for is
  removed). Pass `PendingPolicy::Certify` to keep them instead.
- **A refused revoke is never silently dropped.** If the domain rejects a removal — the
  classic case is removing an organization's **last owner** — the item is recorded as
  un-applied with the reason and audited (`governance.access.revoke_blocked`).
- **Overdue campaigns auto-close.** `cbox-id:governance:close-overdue` (scheduled every
  minute, config-gated) closes any open campaign past its `due_at`, reconstructing each
  campaign's environment first.

## Segregation of Duties

```php
use Cbox\Id\Governance\Contracts\SegregationOfDuties;

$sod = app(SegregationOfDuties::class);

// "Raise a purchase order" and "approve payment" must never be held together.
$sod->definePolicy('acme', 'PO vs payment', [$createPoRoleId, $approvePayRoleId]);

// Pre-grant gate — call BEFORE assigning a role:
if ($sod->wouldViolate('acme', $userId, $approvePayRoleId)) {
    // refuse — the user already holds the conflicting role
}

// Or get a reasoned decision (the same Decision value object the authorization PDP uses):
$decision = $sod->evaluate('acme', $userId, $approvePayRoleId); // deny reason: "sod:{policyId}"

// Detect conflicts that already exist (a report, or to seed a campaign):
$sod->violationsFor('acme', $userId); // this subject's violations
$sod->scan('acme');                   // every violation in the org
```

A policy names a **mutually-exclusive set of roles**; holding two or more at once is a
violation. Policies can be scoped to one organization or made environment-wide
(`organizationId: null`). Inactive policies are ignored.

## Honest scope

- **v1 governs roles and memberships only.** These are the two subject-centric grants
  that are cleanly enumerable and immediately revocable. Deliberately out of scope:
  - **Entitlements** are a billing-fed projection — governed at the billing source, not
    re-certified here (and a `Claims`-mode entitlement's revoke isn't immediate anyway).
  - **ReBAC relationship tuples** have no enumeration or audit surface yet; certifying
    them needs that groundwork first.
- **Certification acts on DIRECT grants.** Role roll-down is computed at read time, so a
  role inherited from an ancestor org is reviewed and revoked **at that ancestor**, where
  the assignment physically lives — revoking there removes the inherited access from the
  whole subtree at once. A campaign scoped to org X governs the grants made at X. SoD
  evaluation likewise considers direct assignments at the org.
- **This is a primitive, not a policy.** Who reviews, how often, and what combinations
  are toxic is the host's decision; the module enforces the mechanics — snapshot,
  decision, application, conflict detection — and audits all of it.

## Where to go next

- [Run an access review](../cookbook/run-an-access-review.md) — the campaign recipe.
- [Security: access governance](../security/governance.md) — the threat model.
