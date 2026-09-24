---
title: Staff roles & support access
description: Give an app vendor's own staff rights across every customer of one app, keep those roles out of tenants' hands, and let staff act as a customer's user with the RFC 8693 act claim
weight: 18
---

# Staff roles & support access

An app vendor's support people and administrators are not members of their customers'
organizations, yet they need to work across all of them — in **one** app. Three pieces
make that possible without handing out more than that:

- **Staff roles** — roles a tenant administrator can never grant.
- **Environment-wide grants of one app's role** — rights in every organization, stamped
  only into that app's tokens.
- **Support sessions** — signing in to the app *as* one customer's user, for a stated
  reason and at most an hour, with every token naming who is really holding it.

## Staff roles: `tenant_assignable`

Every role has a `tenant_assignable` flag, `true` by default. `false` marks a **staff
role**: the organization (tenant) plane never lists it and refuses its id.

An app declares one in its manifest:

```json
{
  "version": "2026-09-24",
  "permissions": [
    { "key": "parcels:read" },
    { "key": "support:impersonate", "description": "Act as a customer's user" }
  ],
  "roles": [
    { "key": "viewer", "name": "Viewer", "permissions": ["parcels:read"] },
    {
      "key": "support",
      "name": "Support",
      "permissions": ["parcels:read", "support:impersonate"],
      "tenant_assignable": false
    }
  ]
}
```

The value must be a JSON boolean. `"false"` as a string, `0`, or `null` refuses the whole
manifest: the default is the permissive one, so a value that cannot be read unambiguously
must not quietly become "every tenant may grant this". A role defined by hand takes the
flag too — `Roles::define(null, 'Support', tenantAssignable: false)` — and
`Roles::updateRole(..., tenantAssignable: false)` changes it, with before and after on the
`role.updated` audit entry.

Both flags count toward the manifest checksum, so a deploy that flips only a role to
staff-only, or only a permission's `tenant_assignable`, re-syncs. Each is added to the
canonical form only in its non-default state — a role's `false`, a permission's `true` (a
permission is internal unless it opts in) — so a manifest that never mentions either hashes
exactly as before and no SDK's checksum drifts. The shared fixture
(`tests/Fixtures/AccessControl/manifest_hash.json`) has a case for each.

### The two planes

| Plane | Call | Grants a staff role? |
| --- | --- | --- |
| Organization (tenant admin) | `Roles::assignAsTenant()` | **No** — refused with `RoleNotTenantAssignable` |
| Organization, listing | `Roles::tenantAssignableRoles($org, $clientId)` | Never listed |
| Environment (environment admin) | `Roles::assign()` | Yes, inside that one organization |
| Environment, everywhere | `Roles::assignEverywhere()` | Yes, in every organization |

```php
use Cbox\Id\AccessControl\Contracts\Roles;

$roles = app(Roles::class);

// A tenant console: offer what this tenant may grant, and grant through the guard.
$offered = $roles->tenantAssignableRoles($organizationId, $clientId);
$roles->assignAsTenant($organizationId, $userId, $roleId); // refuses a staff role

// The environment console: staff rights inside one customer only.
$roles->assign($organizationId, $supportLeadId, $supportRoleId);
```

The list and the guard share one query (the `Role::tenantAssignable()` scope), so a role the
picker hides is exactly a role the write refuses. `RoleNotTenantAssignable` extends
`UnknownRole`, so an existing "not found" mapping keeps working — and a tenant cannot
probe which staff roles exist.

Directory group mappings are a tenant-plane surface too: the customer's IdP decides who is
in a group, so a staff role mapped to one would be handed out by the customer.
`GroupRoleMappings::map()` refuses a staff role, and a mapping whose role *later* becomes
staff-only stops granting it at the next reconcile (the pushed grant is withdrawn, as for an
orphaned role). Manual grants made before a role became staff-only are kept.

## Environment-wide grants of one app's role

`Roles::assignEverywhere($userId, $roleId)` accepts any non-orphaned role that no
organization owns:

- `client_id` null — an app-agnostic role, stamped into **every** app's token;
- `client_id` set — that app's own role, stamped into **that app's** tokens only.

```php
$support = $roles->define(null, 'Support', clientId: $cadastreClientId, tenantAssignable: false);
$roles->grantPermission(null, $support->id, 'support:impersonate');

$roles->assignEverywhere($staffUserId, $support->id);
// Every cadastre token for this person, in any organization or none, carries
// roles: ["Support"]. A tax-app token for the same person carries nothing from it.
```

The token issuer filters an environment-wide grant by client exactly as it filters an
organization grant. An organization's own role is still refused, and segregation-of-duties
policies are still asked in every organization the person belongs to.
`role.assigned_everywhere` and `role.unassigned_everywhere` carry the role's `client_id`, so
a downstream mirror knows which app the grant reaches.

Environment-wide grants are reviewed by the environment's own access review — see
[Access governance](access-governance.md#environment-wide-grants).

## Support sessions

A support session lets a staff member (or an environment administrator) sign in to one
app as one member of one organization. The app completes an ordinary
authorization-code exchange; what it gets back is different in three ways:

- every access token and ID Token carries the RFC 8693 actor claim,
  `"act": {"sub": "<actor id>"}` (introspection returns it too);
- there is **never** a refresh token;
- nothing outlives the session (at most 60 minutes, configurable lower).

```php
use Cbox\Id\OAuthServer\Contracts\SupportSessions;
use Cbox\Id\OAuthServer\Enums\SupportActorKind;
use Cbox\Id\OAuthServer\ValueObjects\NewSupportSession;
use Cbox\Id\OAuthServer\ValueObjects\SupportCodeRequest;

$started = app(SupportSessions::class)->begin(
    new NewSupportSession(
        actorId: $staffUserId,
        actorKind: SupportActorKind::Staff,
        targetUserId: $customerUserId,
        organizationId: $organizationId,
        clientId: $cadastreClientId,
        reason: 'Ticket 4411: invoice totals look wrong',
        ttlSeconds: 1800,
    ),
    // Optional: mint the first code now, bound to the app's PKCE challenge.
    new SupportCodeRequest('https://cadastre.example/callback', $codeChallenge, $nonce),
);

$started->session; // SupportSession — id, expires_at, …
$started->code;    // the app redeems this at /oauth/token like any other code
```

`begin()` refuses — with `SupportSessionRefused`, whose `$refusal` names the check — when:

| Refusal | When |
| --- | --- |
| `ReasonRequired` | The reason is blank. The reason is shown to the customer. |
| `SelfImpersonation` | Actor and target are the same person. |
| `UnknownClient` / `ClientNotEligible` | The app does not exist, is not a first-party app **the environment owns**, or does not use the authorization-code grant. See the consent note below. |
| `NoRedirectUri` / `RedirectUriNotRegistered` | The app cannot complete a sign-in, or the code request names an unregistered redirect URI. |
| `OrganizationInactive` | The organization is suspended or deleted. |
| `TargetNotMember` | The target is not an **active** member (invited and suspended members are refused). |
| `NotPermitted` | A `Staff` actor does not hold the app's own `support:impersonate` through an **environment-wide** grant. |

Who may start one:

- **`SupportActorKind::Staff`** — the framework checks `StaffAccess::holdsEverywhere()`:
  an environment-wide grant of a non-orphaned role (app-agnostic, or this app's) carrying a
  permission named `support:impersonate` **declared by this app**. Holding it inside one
  organization does not count — that is the customer's support, not the vendor's. An app
  that never declares `support:impersonate` has not opted in, and its staff cannot start
  sessions for it.
- **`SupportActorKind::EnvironmentAdmin`** — authorized by the caller. The framework cannot
  know who administers an environment; the console that calls `begin()` asserts it, the
  same way it asserts the environment plane everywhere else.

After it starts:

- `issueCode($sessionId, $actorId, $codeRequest)` mints another single-use code for an
  active session — only for the session's own actor. Use it when the app starts a new
  authorization request while the session is open.
- `end($sessionId, $endedBy)` ends it now: outstanding codes die and every access token it
  minted is revoked. Ending is idempotent.
- `active($sessionId)` and `openFor($actorId)` read open sessions.

Both sides are audited — `support_session.started` and `support_session.ended` on the
organization's trail (who acted as your member, and why) and on the environment's trail
(what the vendor's staff did). `support_session.started` is also emitted as a domain event
scoped to the organization, and is in the webhook catalogue, so the customer's own webhooks
hear about it.

### What an app does with `act`

Treat a token with `act` as "somebody else is here as this user". Show a banner, and refuse
what a support person must never do on a customer's behalf (change their password, move
money, accept terms). The token's `sub` is still the customer, so everything the customer
could see renders as they would see it.

Configuration:

```php
// config/cbox-id.php
'oauth' => [
    'support_sessions' => [
        // Longest a session (and every token minted for it) may live. Only lowers the
        // fixed one-hour ceiling; nothing goes below 60 seconds.
        'max_ttl' => env('CBOX_ID_SUPPORT_SESSION_MAX_TTL', 3600),
    ],
],
```

## Where to go next

- [Security: support sessions](../security/support-sessions.md) — the consent decision,
  what cannot be renewed or laundered, and the limits of revocation.
- [Access governance](access-governance.md) — reviewing environment-wide grants.
- [Custom RBAC](../extension-points/custom-rbac.md) — `StaffAccess` under your own backend.
