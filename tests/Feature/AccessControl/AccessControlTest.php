<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\AccessControl\Contracts\Roles;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('grants a permission through a role assignment', function (): void {
    $org = $this->makeOrganization();
    $this->grantRole('user_1', $org->id, 'admin', ['members.invite', 'billing.read']);

    $checker = app(AccessChecker::class);

    expect($checker->can('user_1', 'members.invite', $org->id))->toBeTrue()
        ->and($checker->can('user_1', 'billing.read', $org->id))->toBeTrue();
});

it('denies by default', function (): void {
    $org = $this->makeOrganization();
    $this->grantRole('user_1', $org->id, 'member', ['docs.read']);

    $checker = app(AccessChecker::class);

    expect($checker->can('user_1', 'billing.read', $org->id))->toBeFalse()   // permission not granted
        ->and($checker->can('user_2', 'docs.read', $org->id))->toBeFalse();   // user not assigned
});

it('lists a user\'s effective permissions', function (): void {
    $org = $this->makeOrganization();
    $this->grantRole('user_1', $org->id, 'admin', ['a', 'b']);

    expect(app(AccessChecker::class)->permissionsFor('user_1', $org->id))
        ->toContain('a', 'b')
        ->toHaveCount(2);
});

it('rolls roles down from an ancestor org (reseller management)', function (): void {
    $reseller = $this->makeOrganization('Reseller');
    $customer = $this->makeOrganization('Customer', parentId: $reseller->id);

    // A support role granted at the reseller applies to the customer beneath it.
    $this->grantRole('support_1', $reseller->id, 'support', ['tickets.manage']);

    $checker = app(AccessChecker::class);

    expect($checker->can('support_1', 'tickets.manage', $customer->id))->toBeTrue()
        ->and($checker->can('support_1', 'tickets.manage', $reseller->id))->toBeTrue();
});

it('does not leak roles upward or sideways', function (): void {
    $reseller = $this->makeOrganization('Reseller');
    $customer = $this->makeOrganization('Customer', parentId: $reseller->id);
    $other = $this->makeOrganization('Other');

    $this->grantRole('user_1', $customer->id, 'member', ['x']);

    $checker = app(AccessChecker::class);

    expect($checker->can('user_1', 'x', $reseller->id))->toBeFalse()  // child role does not roll UP
        ->and($checker->can('user_1', 'x', $other->id))->toBeFalse();  // nor sideways
});

it('emits an event and records audit on assignment', function (): void {
    $org = $this->makeOrganization();
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();

    $role = app(Roles::class)->define($org->id, 'admin');
    app(Roles::class)->assign($org->id, 'user_1', $role->id);

    $events->assertEmitted('role.assigned');
    $audit->assertRecorded('role.assigned');
});
