---
title: Feature flags
description: Switches per environment, on for named users, named organizations or a stable percentage, evaluated from a cache and delivered in the feature_flags claim
weight: 20
---

# Feature flags

A feature flag (`Cbox\Id\FeatureFlags\`) is a named switch your app asks about for one
person in one organization: "is `new-dashboard` on for Ada at Acme?". Flags live in the
identity platform rather than in each app so that every app, and every token, gives the
same answer — and so turning a feature on for a customer is one change, not a deploy.

The app gets the answer three ways:

- **in the token** — a client granted the `feature_flags` scope gets a `feature_flags`
  claim on the access token, the ID token and UserInfo;
- **by asking** — `FeatureFlags::isEnabled()`, `evaluate()`, `forSubject()` and
  `evaluateAll()` on the server, which a host can expose over HTTP to app backends;
- **by webhook** — `feature_flag.created`, `feature_flag.updated` and
  `feature_flag.deleted` when a flag changes.

## What a flag is

| Field | Meaning |
|---|---|
| `key` | What code asks for: `new-dashboard`, `billing.v2`. 1–64 characters, lowercase letters and digits with `-`, `_` or `.` between them. Unique per environment, fixed once created. |
| `description` | Optional, up to 500 characters. |
| `enabled` | The kill switch. Off means off for everyone, whatever the rules say. New flags are enabled. |
| `default_value` | The answer when no rule matches. New flags default to off. |
| user rules | `user id => on/off`. |
| organization rules | `organization id => on/off`. |
| `rollout_percentage` | 0–100, or none. A subject whose stable bucket falls below it gets the flag. |

Flags are **environment-owned**: staging and production have separate flags, and a rule
may only name a user or organization of the same environment. Naming another
environment's id is refused exactly like an id that exists nowhere.

## How a flag is evaluated

First match wins:

1. **Switched off** (`enabled` false) → off. Reason `disabled`.
2. **A user rule** names the subject → that rule's value. Reason `user_target`.
3. **An organization rule** names the organization → that rule's value. Reason
   `organization_target`.
4. **The rollout** — the subject's bucket is below `rollout_percentage` → on. Reason
   `rollout`.
5. **The default** → `default_value`. Reason `default`.

An unknown key is off, with reason `unknown_flag`, so code that ships before its flag
fails closed.

Because rules carry a value, a user rule can switch a flag **off** for one person in an
organization that has it on — and an organization rule can keep a customer out of a
rollout.

A rollout only adds people: someone outside the bucket falls through to the default. With
the default on, a rollout changes nothing; turn the default off to roll out.

### The rollout bucket

```
bucket = int(sha256(key + "/" + identity)[0:8], 16) % 100
```

`identity` is the user id, or the organization id when there is no user (a machine
token, or an organization-only question). With neither there is nothing to bucket and the
default applies. The bucket is:

- **stable** — the same subject gets the same answer on every request and every replica;
- **monotonic** — raising 10% to 20% keeps everyone who was in;
- **salted by the key** — being in the first 10% of one rollout says nothing about the
  next one;
- **reproducible offline** — an SDK can compute it from the formula above.

## Asking from code

```php
use Cbox\Id\FeatureFlags\Contracts\FeatureFlags;

$flags = app(FeatureFlags::class);

$flags->isEnabled('new-dashboard', $userId, $organizationId);   // bool
$flags->evaluate('new-dashboard', $userId, $organizationId);    // FlagEvaluation {key, enabled, reason}
$flags->forSubject($userId, $organizationId);                    // ['acme-beta', 'new-dashboard']
$flags->evaluateAll($userId, $organizationId);                   // ['acme-beta' => FlagEvaluation, …]
```

Managing flags:

```php
use Cbox\Id\FeatureFlags\ValueObjects\FeatureFlagChanges;
use Cbox\Id\FeatureFlags\ValueObjects\FlagTargeting;
use Cbox\Id\FeatureFlags\ValueObjects\NewFeatureFlag;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;

$flag = $flags->create(new NewFeatureFlag(
    key: 'new-dashboard',
    description: 'The redesigned dashboard',
    targeting: new FlagTargeting(
        users: [$adaId => true],
        organizations: [$acmeId => true, $globexId => false],
        rolloutPercentage: 10,
    ),
), AuditActor::user($adminId));

$flags->update($flag->id, FeatureFlagChanges::make()->withEnabled(false), $actor);
$flags->update($flag->id, FeatureFlagChanges::make()->withTargeting(FlagTargeting::rollout(50)), $actor);
$flags->delete($flag->id, $actor);
```

`update()` changes only what the `with…()` calls name. `withTargeting()` replaces the
whole rule set — users, organizations and rollout — so what you send is what applies.
`InvalidFeatureFlag` carries a machine `reason` (`invalid_key`, `key_taken`,
`invalid_percentage`, `too_many_rules`, `unknown_user`, `unknown_organization`) and the
`field` it is about; `UnknownFeatureFlag` means no such flag in this environment.

## In the token

Request the `feature_flags` scope (it is a protocol scope, like `groups`: discovery
advertises it, no API can register it, and it survives when a token is narrowed to one
API's audience). The client must hold it in its registered scopes.

```json
{
  "sub": "01J…",
  "org": "01J…",
  "scope": "openid feature_flags",
  "feature_flags": ["acme-beta", "new-dashboard"]
}
```

With the scope the claim is always there, as an empty list when nothing is on. Tokens
carry the flags as they were at minting; a refresh re-reads them; UserInfo is live. A
token-minting hook cannot change the claim once the scope is granted. See
[Token claims](../reference/token-claims.md#feature_flags--the-features-that-are-on).

## Speed and the cache

Every question — a token mint, a UserInfo call, an evaluation — reads one cache entry per
environment (`cbox-id:feature-flags:{environment}`) holding the whole compiled flag set,
and answers in memory. There is no query per flag or per subject.

Any save or delete of a flag or a rule forgets the entry — at the model, so no write path
can miss it — and forgets it again once the surrounding transaction commits, so a reader
in between cannot cache the old rows for a whole TTL. `cache_ttl` is therefore a backstop
for a cache the replicas do not share, not the mechanism.

```php
'feature_flags' => [
    'cache_ttl' => env('CBOX_ID_FEATURE_FLAGS_CACHE_TTL', 300), // seconds; 0 = always read the database
    'max_rules' => env('CBOX_ID_FEATURE_FLAGS_MAX_RULES', 1000), // user + organization rules per flag
],
```

`max_rules` keeps the cached set small: a flag that lists every user is a cache entry the
size of the user table. Target an organization or use a rollout instead.

## Audit, webhooks and erasure

- Every change is audited — `feature_flag.created`, `feature_flag.updated` (with
  `changes`, the targeting as a diff of rules set and removed) and `feature_flag.deleted`
  — under the `AuditActor` the caller passes, or `system`.
- The same three names are emitted as [webhook events](../reference/webhook-events.md). A
  change that changes nothing emits nothing.
- Erasing a user (GDPR Art. 17) deletes every rule that names them (step
  `feature_flags.targets`).

## Testing

`InteractsWithFeatureFlags` ships with the package:

```php
use Cbox\Id\FeatureFlags\Testing\InteractsWithFeatureFlags;
use Cbox\Id\FeatureFlags\ValueObjects\FlagTargeting;

uses(InteractsWithFeatureFlags::class);

it('shows the beta to Acme only', function () {
    $this->createFeatureFlag('new-dashboard', FlagTargeting::organizations([$acme->id]));

    $this->assertFeatureEnabled('new-dashboard', $user->id, $acme->id);
    $this->assertFeatureDisabled('new-dashboard', $user->id, $globex->id);
});
```

## Not supported

Boolean flags only — no multivariate values or payloads. No scheduled changes, no rules on
arbitrary user attributes, no per-environment promotion of a flag. Evaluation is
server-side; an SDK reads the claim or calls the host's endpoint.
