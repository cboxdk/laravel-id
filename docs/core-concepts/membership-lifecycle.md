---
title: Membership lifecycle
description: Joining, changing tier, leaving, transferring ownership and archiving an organization — the single-owner rule and the events each step emits
weight: 11
---

# Membership lifecycle

Every change to who belongs to an organization goes through the `Memberships`,
`Invitations` and `Organizations` contracts. Each verb enforces the organization's
invariants inside one transaction, records an audit entry and emits a
[webhook event](../reference/webhook-events.md) — so a host never writes a role or a status
onto a model by hand.

## The single-owner rule

An organization always has an owner, and ownership is **transferred, never assigned**.

- `MembershipRole::assignable()` lists the tiers a console or API may hand out — `Owner` is
  not among them. Validate one incoming tier with `$role->isAssignable()` and route a
  request for `Owner` to `transferOwnership()` instead.
- The last owner cannot be demoted, removed or leave: those raise `LastOwner`. The count of
  owners is taken with the owner rows locked, so two owners stepping down at the same moment
  cannot both succeed.
- `owners($organizationId)` lists the active owners. Organizations created before ownership
  was transfer-only may hold more than one; treat that as data to reconcile, not a
  pattern to extend.

## The verbs

| Verb | Contract | What it does | Refusals |
|---|---|---|---|
| Invite | `Invitations::invite()` | Creates a pending invitation; supersedes an earlier pending one to the same address. | — |
| Accept | `Invitations::accept()` | Creates the membership with the invited tier. | `InvalidInvitation` |
| Revoke invitation | `Invitations::revoke()` | Stops a pending invitation's token working. Bound to the organization; idempotent. | — |
| Add | `Memberships::add()` | Adds a member directly. | `CrossEnvironmentAccess` |
| Change tier | `Memberships::changeRole()` | Moves a member to another tier. | `LastOwner` (demoting the only owner) |
| Remove | `Memberships::remove()` | An administrator removes a member and every role they held there. | `LastOwner` |
| Leave | `Memberships::leave()` | The member removes themselves, with every role they held there. Idempotent. | `LastOwner::leaving()` for the only owner |
| Transfer ownership | `Memberships::transferOwnership()` | Owner → an existing active member. The new owner becomes `owner`, the previous one `admin`. | `OwnershipTransferRefused` |
| Rename | `Organizations::update()` | Changes the name and/or slug. | `SlugAlreadyTaken` |
| Archive (operator) | `Organizations::archive()` | Terminal status; access revoked everywhere. Idempotent. | — |
| Archive (owner) | `Organizations::archiveAsOwner()` | The same archive, on an active owner's say-so. | `NotOrganizationOwner` |

### Leaving

```php
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Exceptions\LastOwner;

try {
    app(Memberships::class)->leave($organizationId, $userId);
} catch (LastOwner $e) {
    // "You are the only owner of organization [...], so you cannot leave it.
    //  Transfer ownership to another member first, or archive the organization."
    return back()->withErrors(['leave' => $e->getMessage()]);
}
```

### Transferring ownership

```php
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Exceptions\OwnershipTransferRefused;

try {
    $newOwner = app(Memberships::class)->transferOwnership($organizationId, $currentOwnerId, $memberId);
} catch (OwnershipTransferRefused $e) {
    // $e->reason is an OwnershipTransferRefusal: not_owner, target_not_member,
    // target_not_active or same_member — a stable code for an API error body.
}
```

Both membership rows are read with a row lock, in one statement ordered by id, so the
transfer is atomic against a concurrent remove, leave, role change or second transfer, and
two transfers crossing between the same people cannot deadlock. The organization is never
without an owner at any point in the transaction.

### An owner archiving their organization

`archiveAsOwner($organizationId, $userId)` has exactly `archive()`'s semantics — the
`Deleted` status, the cache invalidation, idempotence — plus a check that `$userId` holds an
active owner membership, taken under a row lock so an ownership transfer cannot slip in
between the check and the archive. The audit entry is attributed to that user.

## Isolation

Every guard above binds the organization in its `WHERE` clause as well as relying on the
tenant scope. Under `TenantContext::withoutScope()` — a provisioning job, a backfill — a
guard that relied on the scope alone would see every organization's rows: a delete would
remove the person everywhere, the owner count would include other organizations' owners,
and a transfer could promote a member of a different organization.

## Events

| Change | Event | Also emitted (legacy name) |
|---|---|---|
| A member joins | `membership.created` | `organization.member_added` |
| A tier changes (incl. a transfer, one per side) | `membership.updated` (`reason`: `role_changed` or `ownership_transferred`) | `organization.member_role_changed` |
| A member is removed or leaves | `membership.deleted` (`reason`: `removed` or `left`) | `organization.member_removed` |
| An invitation is sent | `invitation.created` | `organization.invitation_created` |
| An invitation is accepted | `invitation.accepted` | `organization.invitation_accepted` |
| An invitation is revoked or superseded | `invitation.revoked` (`reason`: `revoked` or `superseded`) | — |
| A rename or settings change | `organization.updated` | — |
| An archive | `organization.deleted` | `organization.archived` |

The legacy names stay because outbound provisioning and usage metering key off them, and
existing webhook endpoints may subscribe to them by name. New integrations subscribe to the
first column. Payloads: [Webhook events](../reference/webhook-events.md).

The member's tier also travels in tokens as the
[`org_role` claim](../reference/token-claims.md#org_role--the-membership-tier).
