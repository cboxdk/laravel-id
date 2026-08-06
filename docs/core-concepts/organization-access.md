---
title: Organization access
description: Ordered membership roles, groups, resource grants, effective-role resolution, and user API tokens with an issuer-role cap
weight: 10
---

# Organization access

The org-plane authorization model: who a member is (an ordered role), what
extra access they hold (grants on host-defined resources, directly or through
groups), and how a machine acts as them (a user API token whose scope is
capped at the issuer's role). Everything is built on the
[relationship-tuple kernel](authorization.md) — grants **are** tuples, so the
boolean decision plane resolves them with no extra wiring.

## Ordered membership roles

`MembershipRole` is strictly ordered: **Owner > Admin > Developer > Member >
Viewer** (`weight()`, `outranks()`). Two capability checks cover the common
gates: `canManageOrganization()` (Owner/Admin) and `canWrite()` (everyone but
Viewer). Hosts wanting the four-tier Owner/Admin/Developer/Viewer model simply
never assign `Member`.

## Groups

`Groups` (contract) manages organization-local groups. The `user_groups` table
holds metadata only — membership lives as relationship tuples
(`user_group:<id> #member @user:<id>`), so there is exactly one membership
store and group-inherited access resolves through the kernel's userset
expansion. Deleting a group deletes its memberships **and** every grant held
through it — no dangling access.

## Resource grants & effective role

`ResourceAccess` (contract) grants a role to a user or a group on a
host-defined `ResourceRef` — the package does not know what a "project" is;
a project-wide grant is a grant on the project's own ref, a row-level grant is
a grant on that row's ref.

The single query surface is `effectiveRole($org, $userId, ...$resources)`:
the highest-weighted role across the user's **active** membership and every
grant matching the given refs, held directly or via any group. Null means no
access (deny-by-default). A grant can raise, never lower, the effective role.

Because grants are tuples, `PolicyDecisionPoint::can($org, $subject, 'developer',
$ref)` also answers exact-role checks — including through groups — but note
raw PDP relations are exact-match: they do not imply lower roles. Use
`effectiveRole()` when ordering matters.

## User API tokens

`UserApiTokens` (contract) issues `cbid_pat_…` bearer credentials that
authenticate **as the user** within one organization — authorization stays
with the user's effective role; there is no token-specific grant model.

- SHA-256-hashed at rest, looked up by hash (no timing oracle); non-secret
  `prefix` fragment for listings; `last_used_at` stamped on resolve.
- Every token carries a hard expiry — `cbox-id.user_api_tokens.default_ttl_days`
  (90) applies when no explicit expiry is given.
- Coarse scope (`read` / `write` / `admin`) plus an optional resource-family
  list (`null` ⇒ unrestricted); enforce families in your API layer via
  `UserApiToken::allowsFamily()`.
- **Issuer-role cap, enforced in the service:** a token never out-ranks its
  minter. `admin` scope requires an org-managing role, `write` a writing role,
  and a non-member mints nothing (`TokenScopeExceedsIssuerRole`).

## Testing

`InteractsWithAccess` ships the helpers the package's own suite uses:

```php
$group = $this->makeGroup($org->id, 'Engineering', members: ['user_1']);
$this->grantAccess($org->id, GrantSubject::group($group->id), MembershipRole::Developer, ResourceRef::of('project', 'p1'));

expect($this->effectiveRole($org->id, 'user_1', ResourceRef::of('project', 'p1')))
    ->toBe(MembershipRole::Developer);
```
