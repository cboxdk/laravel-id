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

it('lists members of an organization and organizations of a user', function (): void {
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B');
    $memberships = app(Memberships::class);

    $memberships->add($a->id, 'user_1', 'owner');
    $memberships->add($a->id, 'user_2', 'member');
    $memberships->add($b->id, 'user_1', 'admin');

    expect($memberships->forOrganization($a->id)->pluck('user_id')->all())->toEqualCanonicalizing(['user_1', 'user_2'])
        ->and($memberships->forOrganization($b->id))->toHaveCount(1)
        ->and($memberships->forUser('user_1')->pluck('organization_id')->all())->toEqualCanonicalizing([$a->id, $b->id])
        ->and($memberships->forUser('user_2'))->toHaveCount(1);
});

it('emits an event and records audit on member add', function (): void {
    $org = $this->makeOrganization();
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();

    app(Memberships::class)->add($org->id, 'user_1', 'member');

    $events->assertEmitted('organization.member_added');
    $audit->assertRecorded('organization.member_added');
});

it('refuses to demote or remove the sole owner', function (): void {
    $org = $this->makeOrganization();
    $memberships = app(Memberships::class);
    $memberships->add($org->id, 'owner_1', 'owner');
    $memberships->add($org->id, 'admin_1', 'admin');

    // The lone owner cannot be demoted or removed — it would orphan the org.
    expect(fn () => $memberships->changeRole($org->id, 'owner_1', 'member'))
        ->toThrow(\Cbox\Id\Organization\Exceptions\LastOwner::class)
        ->and(fn () => $memberships->remove($org->id, 'owner_1'))
        ->toThrow(\Cbox\Id\Organization\Exceptions\LastOwner::class);

    // With a second owner present, either is allowed.
    $memberships->add($org->id, 'owner_2', 'owner');
    $memberships->changeRole($org->id, 'owner_1', 'member');
    expect($memberships->of($org->id, 'owner_1')?->role)->toBe('member');
});
