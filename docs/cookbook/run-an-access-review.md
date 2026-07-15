---
title: Run an access review
description: Open a certification campaign, record certify/revoke decisions, and apply them on close
weight: 42
---

# Run an access review

Periodically review who holds access in an organization and remove what is no longer
needed. Everything runs inside an [environment](../core-concepts/environments.md).

## 1. Open a campaign

```php
use Cbox\Id\Governance\Contracts\AccessReviews;

$reviews = app(AccessReviews::class);

$campaign = $reviews->open(
    organizationId: 'acme',
    name: 'Q3 access review',
    dueAt: now()->addWeek(),          // overdue campaigns auto-close
    // pendingPolicy: PendingPolicy::Revoke  (default — un-reviewed access is removed)
    createdBy: $admin->id,
);
```

Opening snapshots every **direct** role assignment and membership in the org as a
pending item.

## 2. Route items to reviewers and record decisions

```php
foreach ($reviews->itemsFor($campaign->id) as $item) {
    // $item->subject_id holds $item->access_ref ($item->access_type = role | membership)
    // Show it to the right reviewer (e.g. the subject's manager), then:

    if ($accessStillNeeded) {
        $reviews->certify($item->id, reviewerId: $manager->id);
    } else {
        $reviews->revoke($item->id, reviewerId: $manager->id, note: 'role change');
    }
}
```

Decisions are reversible while the campaign is open — `revoke()` only records intent.

## 3. Close to apply

```php
$reviews->close($campaign->id);
```

Close removes every revoked grant (`Roles::unassign()` / `Memberships::remove()`),
applies the `PendingPolicy` to anything left un-reviewed, and marks the campaign
closed. Inspect the result:

```php
foreach ($reviews->itemsFor($campaign->id) as $item) {
    $item->decision;          // certified | revoked
    $item->applied;           // false if the domain refused (e.g. last owner)
    $item->application_note;  // the reason, when blocked
}
```

Or let it run itself: with the scheduler enabled, `cbox-id:governance:close-overdue`
closes any campaign past its `dueAt` automatically.

## Prevent toxic combinations up front

Pair reviews with [Segregation of Duties](../core-concepts/access-governance.md#segregation-of-duties):
call `SegregationOfDuties::wouldViolate()` before assigning a role so a conflicting
grant is refused at the source, and `scan()` to feed existing violations into your next
campaign. See [Security: access governance](../security/governance.md).
