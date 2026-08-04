---
title: Account roles vs. membership roles
description: How AccountRole and MembershipRole correspond, where they genuinely differ, and the only safe mapping in each direction
weight: 11
---

# Account roles vs. membership roles

An account **is** an organization in the platform root — that is the whole premise of
[accounts and projects](accounts-and-projects.md). But the two planes carry two
different role enums, and they are **not** the same set under two names. Four of the
five cases share a name and an intent; each enum has one case the other does not, and
the predicate surfaces are not interchangeable. Anything that maps one to the other
without reading this is an authorization bug waiting for its first Billing-only member.

- `Cbox\Id\Platform\Enums\AccountRole` — who may administer the **account**: members,
  billing, environments. Modelled on Stripe's team roles.
- `Cbox\Id\Organization\Enums\MembershipRole` — a member's coarse role **inside an
  organization**, and the base of effective-access resolution against grants and
  groups.

## The cases

| Case | `AccountRole` | `MembershipRole` | Same intent? |
|---|---|---|---|
| `owner` | yes | yes | yes — full control, and neither is casually assignable |
| `admin` | yes | yes | yes — everything short of ownership |
| `developer` | yes | yes | yes — the technical plane, no members, no billing |
| `viewer` | yes | yes | yes — read-only |
| `billing` | **yes** | no | — no organization-plane analogue |
| `member` | no | **yes** | — no account-plane analogue |

## The predicates

Where the two enums answer the same question they agree; where only one answers it,
the other has **no** answer and inferring one is the mistake.

| Question | `AccountRole` | `MembershipRole` |
|---|---|---|
| Administer the entity | `canManageMembers()` — Owner, Admin | `canManageOrganization()` — Owner, Admin |
| Manage billing | `canManageBilling()` — Owner, Admin, Billing | *(none)* |
| Read billing | `canReadBilling()` — Owner, Admin, Billing, Viewer | *(none)* |
| Manage environments | `canManageEnvironments()` — Owner, Admin, Developer | *(none)* |
| Mutate owned resources | *(none)* | `canWrite()` — everyone but Viewer |
| Read the member roster | `canReadMembers()` — Owner, Admin, Viewer | *(none)* |
| Rank against another role | *(none)* | `weight()` / `outranks()` |
| Assignable by a manager | `assignable()` — Owner excluded | *(none)* |

Two rows deserve emphasis:

- **`canWrite()` is broader than `canManageEnvironments()`.** `MembershipRole::Member`
  passes `canWrite()`; there is no account-plane role with that shape. Gating an
  account-plane write on a `canWrite()`-style check grants environment management to a
  role that was never meant to have it.
- **`canReadMembers()` deliberately excludes Developer and Billing** — a leaked CI
  credential must not enumerate the team. `MembershipRole` has no read predicate at
  all, so nothing on the organization plane stops a Developer membership from reading
  the roster. That asymmetry is intentional on the account plane and simply absent on
  the other; do not "fix" it by mapping through.

## The only safe mapping

Both directions are lossy, and each has exactly one case that must be **demoted**
rather than approximated.

`MembershipRole` → `AccountRole`:

| From | To | Why |
|---|---|---|
| `Owner` | `Owner` | |
| `Admin` | `Admin` | |
| `Developer` | `Developer` | |
| `Viewer` | `Viewer` | |
| `Member` | **`Viewer`** | `Member` can write but carries no technical-plane meaning. Mapping it to `Developer` would hand it environment management; `Viewer` is the safe floor. |

`AccountRole` → `MembershipRole`:

| From | To | Why |
|---|---|---|
| `Owner` | `Owner` | |
| `Admin` | `Admin` | |
| `Developer` | `Developer` | |
| `Viewer` | `Viewer` | |
| `Billing` | **`Viewer`** | `Member` is the tempting target and the wrong one: `Member` passes `canWrite()`, and a billing-only member must not gain write access to anything. Billing capability is **not** representable in `MembershipRole` and must be carried separately. |

Neither direction round-trips. `Member → Viewer → Member` loses write access;
`Billing → Viewer → Billing` loses billing entirely. **Do not** persist a
`MembershipRole` and re-derive an `AccountRole` from it, or the reverse — a mapping is
for a single decision at a single call site, never for storage.

## Not unified, on purpose

They stay two enums for now. The account plane's split of "manage members" from
"manage billing" from "manage environments" is real product surface (Stripe's model),
and the organization plane's ordered `weight()` is load-bearing for effective-access
resolution across memberships, grants and groups. Collapsing them would mean either
importing `Billing` into every organization or dropping a capability the account
console already sells. The correspondence above is what the app needs; unification, if
it ever happens, is a separate decision with its own migration.

`tests/Feature/Platform/AccountAndMembershipRoleMappingTest.php` locks every claim on
this page, so a new case in either enum turns this doc red rather than stale.
