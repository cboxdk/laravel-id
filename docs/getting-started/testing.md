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

```php
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
