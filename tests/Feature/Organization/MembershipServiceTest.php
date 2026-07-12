<?php

declare(strict_types=1);

use Cbox\Id\Organization\Contracts\Memberships;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('adds a member scoped to the organization', function (): void {
    $org = $this->makeOrganization();
    $membership = app(Memberships::class)->add($org->id, 'user_1', 'admin');

    expect($membership->organization_id)->toBe($org->id)
        ->and($membership->role)->toBe('admin')
        ->and(app(Memberships::class)->of($org->id, 'user_1')?->id)->toBe($membership->id);
});

it('isolates memberships between organizations', function (): void {
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B');

    app(Memberships::class)->add($a->id, 'user_1', 'member');

    expect(app(Memberships::class)->of($b->id, 'user_1'))->toBeNull()
        ->and(app(Memberships::class)->of($a->id, 'user_1'))->not->toBeNull();
});

it('changes a role and removes a member', function (): void {
    $org = $this->makeOrganization();
    $memberships = app(Memberships::class);

    $memberships->add($org->id, 'user_1', 'member');
    $memberships->changeRole($org->id, 'user_1', 'admin');
    expect($memberships->of($org->id, 'user_1')?->role)->toBe('admin');

    $memberships->remove($org->id, 'user_1');
    expect($memberships->of($org->id, 'user_1'))->toBeNull();
});

it('emits an event and records audit on member add', function (): void {
    $org = $this->makeOrganization();
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();

    app(Memberships::class)->add($org->id, 'user_1', 'member');

    $events->assertEmitted('organization.member_added');
    $audit->assertRecorded('organization.member_added');
});
