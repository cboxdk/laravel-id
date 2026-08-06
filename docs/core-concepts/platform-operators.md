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

The operator's SUBJECT is a different matter: subjects are environment-owned like
everything else, so it lives in the platform root and is read there. The record that
grants authority is above the boundary; the credential behind it is an ordinary row in
one environment. Keeping those apart is what lets authority be global without giving
the credential a second, unpoliced home.

## The credential is a subject, not a second password column

`platform_operators` once held an email and a hash and nothing else — a second
credential store beside the subject one. Everything that protects a sign-in on this
platform lives on the SUBJECT: password policy, breached-password refusal, lockout
after repeated failures, TOTP, passkeys, step-up, session revocation. An operator had
none of it, so the widest reach in the product sat behind the weakest door, and it was
weakest precisely because it was separate.

`platform_operators.subject_id` points at an ordinary subject in the **platform
root** — the environment the platform's own people live in — and
`verifyPassword()` asks that subject. The local hash column is **bootstrap only**: it
is the credential for an operator created before a platform root existed, and the
subject is attached on that operator's next successful sign-in, the one moment the
plaintext is available to seed one.

What this means for a host:

- **Do not stand up a second sign-in door for operators.** There is one credential
  and therefore one door. Authenticate the subject the way you authenticate anybody,
  then ask `findBySubject()` whether the person you just signed in runs the
  deployment. Staff pages become a PERMISSION on the session you already have, in the
  same shell and the same navigation as every other page.
- **`findBySubject()` excludes suspended operators itself**, rather than leaving the
  status check to each call site. Authority now rides an existing session and
  suspending an operator has never revoked their subject sessions, so a check left to
  the caller fails open — the suspended operator keeps every staff page in the session
  they are already sitting in.
- **A deactivated subject refuses the operator immediately**, at the credential rather
  than at the next session boundary.

```php
// "Is the person in this session staff?" — asked of the one session.
$operator = app(PlatformOperators::class)->findBySubject($subjectId);

if ($operator === null) {
    abort(404); // not staff: the surface does not exist for them
}
```

## How an operator assumes an environment

1. The operator authenticates as their subject, in the platform root — the same
   sign-in every other person on the deployment uses. `findBySubject()` is what says
   that subject is staff (active operators only).
2. The host pins an environment for the request (session-selected, or resolved
   from the host name). That sets the [`EnvironmentContext`](environments.md).
3. Every read and write the operator performs is scoped to the pinned
   environment. The operator record itself stays above the boundary — only the
   *data it touches* belongs to a plane.

So an operator switching from **production** to **staging** does not need an
account in staging: their identity is above both. What changes is only which
plane's data the console reads and writes.

## Provisioning

Operators are created out of band (an installer, a console command, or an existing
operator inviting another). `create()` also gives the operator their subject, reusing
the one they already have if that address is already an account member — two subjects
for one human is the split this design exists to end.

```php
use Cbox\Id\Platform\Contracts\PlatformOperators;

$operators = app(PlatformOperators::class);

// Gate an installer on whether any operator exists yet.
if (! $operators->exists()) {
    $root = $operators->create('root@yourco.example', $password, 'Root Operator');
}

// Authenticate — false for a wrong password, a suspended operator, *or* a
// deactivated subject. Reaches the subject store; the local hash is bootstrap only.
if ($operators->verifyPassword($operator->id, $submittedPassword)) {
    $operators->touchLogin($operator->id);
}
```

### API

| Method | Purpose |
| --- | --- |
| `find(string $id)` | Resolve an operator by id (unscoped). |
| `findByEmail(string $email)` | Resolve by the globally unique email. |
| `findBySubject(string $subjectId)` | The operator record a signed-in subject holds, or null. **Active operators only** — this is how a host gates a staff console as a permission on the one session. |
| `create(string $email, string $password, ?string $name = null)` | Provision an operator, and attach the platform-root subject that is their credential. |
| `verifyPassword(string $id, string $password)` | Verify against the operator's subject, gated on operator status *and* subject status. Falls back to the local hash only for an operator created before a platform root existed. |
| `exists()` | Whether any operator is provisioned (bootstrap gate). |
| `touchLogin(string $id)` | Record a successful sign-in. |
| `suspend(string $id, string $actorId)` | Stop an operator authenticating. Refuses the last active one — that would lock every human out of the control plane. Audited. |
| `reactivate(string $id, string $actorId)` | Undo a suspension. Audited. |

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
