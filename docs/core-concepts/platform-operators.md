---
title: Platform operators
description: The identity above every environment — who administers the planes
weight: 3
---

# Platform operators

An **environment** is the hard isolation boundary. A **platform operator** is the
identity that stands *above* it — the person who provisions environments and can
step into any one of them to run its console. This is the dashboard/developer
account — the staff identity — and it is distinct from the end users who live
*inside* an environment.

| Concept | Cbox ID |
| --- | --- |
| Boundary | Environment |
| Identity inside it | User |
| Identity above it | **Platform operator** |

## Why it is not environment-owned

Every in-environment record — users, organizations, signing keys — carries an
`environment_id` and is invisible from any other environment (deny-by-default).
A platform operator is the deliberate exception: the `platform_operators` table
has **no `environment_id`** and a **globally unique email**. It has to, because an
operator authenticates once and can then assume *any* plane. Scoping it to one
environment would defeat its entire purpose.

The two identities never blur:

- A **user** is bound to exactly one environment. Load it under a different
  environment and the scope returns nothing.
- A **platform operator** resolves identically no matter which environment is
  pinned — it lives above them all.

## How an operator assumes an environment

1. The operator authenticates at the platform level (credentials checked against
   `platform_operators`, gated on active status).
2. The host pins an environment for the request (session-selected, or resolved
   from the host name). That sets the [`EnvironmentContext`](environments.md).
3. Every read and write the operator performs is scoped to the pinned
   environment. The operator record itself stays above the boundary — only the
   *data it touches* belongs to a plane.

So an operator switching from **production** to **staging** does not need an
account in staging: their identity is above both. What changes is only which
plane's data the console reads and writes.

## Provisioning

Operators are created out of band (a first-run bootstrap, a console command, or
an existing operator inviting another). The repository hashes the password with
the configured driver and never re-hashes an already-hashed value.

```php
use Cbox\Id\Platform\Contracts\PlatformOperators;

$operators = app(PlatformOperators::class);

// Gate first-run bootstrap on whether any operator exists yet.
if (! $operators->exists()) {
    $root = $operators->create('root@yourco.example', $password, 'Root Operator');
}

// Authenticate — false for a wrong password *or* a suspended operator.
if ($operators->verifyPassword($operator->id, $submittedPassword)) {
    $operators->touchLogin($operator->id);
}
```

### API

| Method | Purpose |
| --- | --- |
| `find(string $id)` | Resolve an operator by id (unscoped). |
| `findByEmail(string $email)` | Resolve by the globally unique email. |
| `create(string $email, string $password, ?string $name = null)` | Provision an operator; password hashed on the way in. |
| `verifyPassword(string $id, string $password)` | Verify credentials, gated on active status. |
| `exists()` | Whether any operator is provisioned (bootstrap gate). |
| `touchLogin(string $id)` | Record a successful sign-in. |

## Isolation guarantee — and how it's proven

> A platform operator provisioned in one environment resolves, unchanged, from
> every other environment, and carries no `environment_id`.

This is asserted directly in the `@group isolation` suite
(`PlatformOperatorTest`): an operator created inside `env_a` is found by email
from `env_b`, and the table is verified to have no environment column. Run it
with:

```bash
vendor/bin/pest --group=isolation
```
