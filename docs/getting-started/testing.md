---
title: Testing
description: The shippable InteractsWith* helpers and fakes for testing your own code
weight: 6
---

# Testing

Every module ships test ergonomics under a `Testing/` namespace — the same helpers the package
uses to test itself, so they're proven, not aspirational. Compose the traits into your test
case (or `uses()` them in Pest).

```php
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Organization\Testing\InteractsWithOrganizations;
use Cbox\Id\Identity\Testing\InteractsWithIdentity;

uses(InteractsWithTenancy::class, InteractsWithOrganizations::class, InteractsWithIdentity::class);
```

## Setup helpers

| Trait | Helpers |
|---|---|
| `InteractsWithTenancy` | `actingAsTenant()`, `runAsTenant()`, `actingAsTenants()`, `withoutTenantScope()` |
| `InteractsWithOrganizations` | `makeOrganization(name, slug?, parentId?)` |
| `InteractsWithIdentity` | `makeUser(email?, name?, password?)` |
| `InteractsWithAccessControl` | `grantRole(userId, orgId, roleName, permissions)` |
| `InteractsWithEntitlements` | `grantEntitlement(orgId, key, value?, mode?)` |
| `InteractsWithAuthorization` | `relate(Relationship)`, `pdp()` |
| `InteractsWithDirectory` | `makeDirectory(orgId, name?)` |
| `InteractsWithFederation` | `makeConnection(orgId, type?, name?, config?, active?)` |
| `InteractsWithWebhooks` | `registerWebhook(orgId, url, eventTypes)` |
| `InteractsWithOAuth` | `makeClient(scopes?, type?)`, `makeServiceAccount(orgId, scopes?, name?)` |
| `InteractsWithPlatform` | `makeOperator(email?, password?, name?)` |
| `InteractsWithOtp` | `fakeOtpChannel(key?)`, `issueOtp(purpose, recipient, channel?, ip?)`, `verifyOtp(challengeId, code, ip?)` |

> **Establish an environment first.** The domain models are environment-owned and
> deny-by-default: a test that calls `makeOrganization()` or `makeUser()` with **no
> environment in context** gets nothing back (or hits a NOT NULL `environment_id`). Pin one
> in `setUp()` with `actingAsEnvironment('env_test')` (from `InteractsWithTenancy`) — this is
> exactly what the package's own `tests/TestCase.php` does in `setUp()`. Isolation tests
> override it per case.

```php
uses(InteractsWithTenancy::class);

beforeEach(fn () => $this->actingAsEnvironment('env_test')); // the hard outer scope

it('scopes to the acting tenant', function () {
    $org = $this->makeOrganization('Acme');
    $user = $this->makeUser('a@acme.test');
    $this->grantRole($user->id, $org->id, 'admin', ['members.invite']);

    expect(app(AccessChecker::class)->can($user->id, 'members.invite', $org->id))->toBeTrue();
});
```

## Fakes and assertions

The Events and Audit kernels ship assertable fakes, in the spirit of Laravel's `Event::fake()`:

```php
$events = $this->fakeEvents();   // InteractsWithEvents
$audit  = $this->fakeAudit();    // InteractsWithAudit

app(Organizations::class)->create(new NewOrganization('Acme', 'acme'));

$events->assertEmitted('organization.created', fn ($e) => $e->organizationId !== null);
$audit->assertRecorded('organization.created');
$events->assertNotEmitted('organization.deleted');
```

The OTP module ships a `FakeOtpChannel` that captures delivered codes, so a test
can read the code without a real transport:

```php
$channel   = $this->fakeOtpChannel();                       // InteractsWithOtp
$challenge = $this->issueOtp('login', 'a@acme.test');       // over the fake channel
$result    = $this->verifyOtp($challenge->id, $channel->codeFor('a@acme.test'));

expect($result->verified)->toBeTrue();
$channel->assertDelivered('a@acme.test');
```

## Mocking

Every contract is an interface, so mock it directly when you want full control:

```php
$this->mock(Subjects::class)
    ->shouldReceive('findByEmail')
    ->andReturn(null);
```

## Tenant isolation is testable

The most important test in a multi-tenant platform is that data can't leak across tenants. The
package proves this with a `@group=isolation` suite; write the same kind of test for your
tenant-owned models:

```php
it('never leaks across tenants', function () {
    $this->runAsTenant('org_a', fn () => Widget::create(['name' => 'secret']));

    // acting as another tenant sees nothing
    $this->runAsTenant('org_b', function () {
        expect(Widget::count())->toBe(0);
    });

    // and no tenant at all is deny-by-default, not "everything"
    expect(Widget::count())->toBe(0);
});
```
