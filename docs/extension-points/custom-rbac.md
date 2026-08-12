---
title: Custom RBAC (bring your own)
description: Run the platform for AuthN/SSO/OAuth/OIDC while an external authorization backend (e.g. an existing Spatie permission install) is the source of roles, permissions, and token claims
weight: 60
---

# Custom RBAC (bring your own)

The platform ships a hierarchy-aware RBAC of its own — roles roll down an org tree,
app manifests declare per-app roles, and tokens are stamped from the effective set.
But an app that **already** has an authorization backend (for example a Spatie
`laravel-permission` install) can keep it and still adopt everything else the
platform offers: authentication, SSO/SAML, the OAuth/OIDC provider, SCIM, and audit.

You do this by switching the **access-control driver** to `external` and binding your
own implementation of the `AccessChecker` contract. The platform's token issuer and
UserInfo endpoint depend only on that contract, so your roles and permissions flow
straight into the tokens the platform mints.

## 1. Select the external driver

```php
// config/cbox-id.php
'access_control' => [
    'driver' => env('CBOX_ID_ACCESS_CONTROL_DRIVER', 'external'),
    // …
],
```

Under `external` the built-in RBAC tables (`roles`, `permissions`, `role_permission`,
`role_assignments`, `group_role_mappings`, `app_manifests`) and their migrations are
**not** loaded — which is exactly what lets the platform coexist with a Spatie install
that already owns `roles` and `permissions`. Until you bind an adapter, the platform
is **deny-by-default**: `AccessChecker` grants nothing, and the write/sync contracts
(`Roles`, `GroupRoleMappings`) throw `ExternalRbacNotBound` rather than writing to
tables that do not exist.

## 2. Implement `AccessChecker`

`AccessChecker` has three methods (see `Cbox\Id\AccessControl\Contracts\AccessChecker`):

- `can()` — a coarse permission check.
- `permissionsFor()` — the subject's effective permission names in an org.
- `forToken()` — the roles and permissions to stamp into a token minted for one app.

An adapter over an existing Spatie install:

```php
namespace App\Identity;

use App\Models\User;
use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\AccessControl\ValueObjects\AppAccessClaims;

class SpatieAccessChecker implements AccessChecker
{
    public function can(string $userId, string $permission, string $organizationId): bool
    {
        return $this->user($userId, $organizationId)?->can($permission) ?? false;
    }

    /** @return list<string> */
    public function permissionsFor(string $userId, string $organizationId): array
    {
        $user = $this->user($userId, $organizationId);

        return $user ? array_values($user->getAllPermissions()->pluck('name')->all()) : [];
    }

    public function forToken(string $userId, string $organizationId, string $clientId): AppAccessClaims
    {
        $user = $this->user($userId, $organizationId);

        if ($user === null) {
            return new AppAccessClaims([], []);
        }

        return new AppAccessClaims(
            roles: array_values($user->getRoleNames()->all()),
            permissions: array_values($user->getAllPermissions()->pluck('name')->all()),
        );
    }

    private function user(string $userId, string $organizationId): ?User
    {
        // Multi-tenant: map the org onto a Spatie team before resolving, e.g.
        //   app(\Spatie\Permission\PermissionRegistrar::class)
        //       ->setPermissionsTeamId($this->teamFor($organizationId));
        // Single-tenant: ignore $organizationId.
        return User::find($userId);
    }
}
```

## 3. Bind it

A binding in your own service provider wins over the deny-by-default fallback:

```php
// app/Providers/AppServiceProvider.php
use Cbox\Id\AccessControl\Contracts\AccessChecker;

public function register(): void
{
    $this->app->singleton(AccessChecker::class, \App\Identity\SpatieAccessChecker::class);
}
```

That is the whole integration for the read path. Tokens issued by the OAuth/OIDC
provider and the UserInfo endpoint now carry your Spatie roles and permissions.

## What you own under `external`

- **The org dimension.** The platform is hierarchy-aware and always passes an
  `organizationId`; a flat backend can ignore it (single-tenant), or map it onto a
  Spatie *team*. `forToken()` normally scopes roles per `client_id`; a single-app
  backend simply returns all of them.
- **Provisioning writes, if you use them.** SCIM directory-group→role sync and the
  access-governance module call the `Roles` and `GroupRoleMappings` contracts. If you
  drive provisioning into your backend, also implement and bind those; otherwise the
  refusing defaults keep those paths failing loud instead of silently.

## Publishing migrations

The built-in RBAC migrations sit in a subdirectory so the auto-loader can gate them.
`vendor:publish --tag=cbox-id-migrations` still flattens **every** migration into your
`database/migrations`, so if you publish under the `external` driver, delete the six
RBAC files (`*_create_access_control_tables`, `*_add_app_declarations_to_access_control`,
`*_create_group_role_mappings_table`, `*_add_tenant_assignable_to_permissions`,
`*_scope_permissions_to_environment`,
`*_backfill_manual_permission_environments`) before migrating — your backend owns those tables.
