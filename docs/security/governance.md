---
title: Access governance
description: Threat model for access certification + Segregation of Duties — deny-by-default pending, refused-revoke never dropped, environment-isolated, fully audited
weight: 16
---

# Security: access governance

Access governance (`Cbox\Id\Governance\`) exists to make over-provisioned access
visible and removable, so its own controls must be trustworthy. This page states
the threat model and the honest limits.

## Controls

| Control | Mechanism | Where |
| --- | --- | --- |
| Real application | close() applies revokes via `Roles::unassign()` / `Memberships::remove()` — not a paper decision | `DatabaseAccessReviews::applyRevoke()` |
| Safe-by-default pending | items un-reviewed at close are **revoked** by default (`PendingPolicy::Revoke`) | `DatabaseAccessReviews::settle()` |
| Refused revoke is surfaced | a domain-guard refusal (last owner) → item marked un-applied + reason + audit, never dropped | `DatabaseAccessReviews::applyRevoke()`, `governance.access.revoke_blocked` |
| Closed = frozen | no certify/revoke after close; re-close is idempotent (never re-applies) | `DatabaseAccessReviews::decide()` / `close()` |
| SoD gate | reasoned `Decision` (deny carries the policy id) before a grant completes a toxic combo | `DatabaseSegregationOfDuties::evaluate()` |
| Environment scope | campaigns, items and policies are `BelongsToEnvironment` — cross-env invisible | all `Governance\Models\*` |
| Audit correlation | every decision + application audited, correlated by `campaign_id` in `context` | hash-chained audit trail |

## Why pending-defaults-to-revoke

An access review that leaves un-reviewed grants in place is theatre: the grants no
one looked at are exactly the ones most likely to be stale. So the default
`PendingPolicy` is **Revoke** — closing a campaign removes any access nobody
certified, matching the deny-by-default posture of the rest of the platform. A host
that wants a softer review (flag, don't cut) sets `PendingPolicy::Certify`
explicitly and owns that choice.

## The last-owner case, and why it's visible

Removing an organization's sole owner would orphan the org, so `Memberships::remove()`
refuses it (`LastOwner`). Governance does **not** swallow that: the certification item
is recorded as `applied = false` with the reason, and a `governance.access.revoke_blocked`
event is written to the audit trail. A reviewer's revoke that could not be carried out
is a finding, not a no-op — the campaign's evidence shows exactly what was and wasn't
enforced.

## Auditing

`governance.campaign_opened`, `governance.item_certified`, `governance.item_revoked`,
`governance.access.revoked`, `governance.access.revoke_blocked` and
`governance.campaign_closed` are recorded on the hash-chained trail. Decision events
carry the **reviewer** (`AuditEvent::forUser`), and every event carries the
`campaign_id` in its context, so a campaign is fully reconstructable — who reviewed
what, what they decided, and what the system actually applied — from the audit log.
The downstream `Roles::unassign()` / `Memberships::remove()` calls emit their own
`role.unassigned` / `organization.member_removed` events too, so the enforcement is
double-recorded. See [core-concepts/audit-streaming.md](../core-concepts/audit-streaming.md).

## Honest limits

- **Scope: roles + memberships.** Entitlements (billing-fed) and ReBAC tuples are out
  of v1 — see [core-concepts/access-governance.md](../core-concepts/access-governance.md).
- **Direct grants only.** Inherited (rolled-down) access is governed at the ancestor
  where the assignment lives; a campaign does not reach up the hierarchy on the
  descendant's behalf. SoD evaluates direct assignments at the org.
- **SoD is an explicit gate, not an ambient guarantee.** It denies a proposed grant only
  when the host calls `evaluate()`/`wouldViolate()` before assigning. It does not
  retroactively block a role already assigned out-of-band — `scan()`/`violationsFor()`
  are how you find those, and a campaign is how you remediate them.
- **A primitive, not a policy.** Review cadence, reviewer selection and what counts as a
  toxic combination are the host's to decide.
