<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Enums\GrantSource;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Exceptions\LastOwner;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

it('adds a member scoped to the organization', function (): void {
    $org = $this->makeOrganization();
    $membership = app(Memberships::class)->add($org->id, 'user_1', 'admin');

    expect($membership->organization_id)->toBe($org->id)
        ->and($membership->role->value)->toBe('admin')
        ->and(app(Memberships::class)->of($org->id, 'user_1')?->id)->toBe($membership->id);
});

it('isolates memberships between organizations', function (): void {
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B');

    app(Memberships::class)->add($a->id, 'user_1', 'member');

    expect(app(Memberships::class)->of($b->id, 'user_1'))->toBeNull()
        ->and(app(Memberships::class)->of($a->id, 'user_1'))->not->toBeNull();
});

it('counts an organization\'s members with a single count query, not by hydrating them', function (): void {
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B');
    $memberships = app(Memberships::class);

    $memberships->add($a->id, 'user_1', 'member');
    $memberships->add($a->id, 'user_2', 'member');
    $memberships->add($b->id, 'user_3', 'member');

    // Scoped to the org, and served by an aggregate query — not forOrganization()->count().
    $queries = 0;
    DB::listen(function ($q) use (&$queries): void {
        if (str_contains(strtolower($q->sql), 'count(')) {
            $queries++;
        }
    });

    expect($memberships->countForOrganization($a->id))->toBe(2)
        ->and($memberships->countForOrganization($b->id))->toBe(1);

    expect($queries)->toBe(2); // one aggregate per call, no model hydration
});

it('rejects an unknown role instead of persisting a garbage string', function (): void {
    $org = $this->makeOrganization();

    // The role is authorization data (MembershipRole enum) — an invalid value is a
    // ValueError at the boundary, never a silently-stored string that fails open later.
    expect(fn () => app(Memberships::class)->add($org->id, 'user_1', 'superuser'))
        ->toThrow(ValueError::class);
});

it('changes a role and removes a member', function (): void {
    $org = $this->makeOrganization();
    $memberships = app(Memberships::class);

    $memberships->add($org->id, 'user_1', 'member');
    $memberships->changeRole($org->id, 'user_1', 'admin');
    expect($memberships->of($org->id, 'user_1')?->role?->value)->toBe('admin');

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
        ->toThrow(LastOwner::class)
        ->and(fn () => $memberships->remove($org->id, 'owner_1'))
        ->toThrow(LastOwner::class);

    // With a second owner present, either is allowed.
    $memberships->add($org->id, 'owner_2', 'owner');
    $memberships->changeRole($org->id, 'owner_1', 'member');
    expect($memberships->of($org->id, 'owner_1')?->role?->value)->toBe('member');
});

it('paginates an organization roster without hydrating every member', function (): void {
    $org = $this->makeOrganization();
    $memberships = app(Memberships::class);
    foreach (range(1, 5) as $i) {
        $memberships->add($org->id, "user_{$i}", 'member');
    }

    $page = $memberships->paginateForOrganization($org->id, 2);

    expect($page->total())->toBe(5)
        ->and($page->perPage())->toBe(2)
        ->and($page->count())->toBe(2)
        ->and($page->lastPage())->toBe(3)
        ->and($page->items()[0]->user_id)->toBe('user_1'); // oldest-first
});

/**
 * Role assignments are read by (organization, user) with no membership join, so leaving
 * them behind when a member is removed is not untidiness: re-adding the person later
 * silently restores privileges nobody re-granted, and anything reading assignments
 * directly still sees them held.
 */
it('revokes the subject RBAC grants along with the membership', function (): void {
    $org = $this->makeOrganization();
    $memberships = app(Memberships::class);
    $roles = app(Roles::class);

    $memberships->add($org->id, 'user_rbac', 'member');

    $role = $roles->define($org->id, 'billing-admin');
    $roles->assign($org->id, 'user_rbac', $role->id, GrantSource::Manual);

    expect($roles->assignmentsForSubject($org->id, 'user_rbac'))->toHaveCount(1);

    $memberships->remove($org->id, 'user_rbac');

    expect($roles->assignmentsForSubject($org->id, 'user_rbac'))->toBe([]);

    // Re-adding them starts from nothing, rather than restoring what was never re-granted.
    $memberships->add($org->id, 'user_rbac', 'member');
    expect($roles->assignmentsForSubject($org->id, 'user_rbac'))->toBe([]);
});

it('leaves another subject grants alone when one member is removed', function (): void {
    $org = $this->makeOrganization();
    $memberships = app(Memberships::class);
    $roles = app(Roles::class);

    $memberships->add($org->id, 'user_goes', 'member');
    $memberships->add($org->id, 'user_stays', 'member');

    $role = $roles->define($org->id, 'support');
    $roles->assign($org->id, 'user_goes', $role->id, GrantSource::Manual);
    $roles->assign($org->id, 'user_stays', $role->id, GrantSource::Manual);

    $memberships->remove($org->id, 'user_goes');

    expect($roles->assignmentsForSubject($org->id, 'user_goes'))->toBe([])
        ->and($roles->assignmentsForSubject($org->id, 'user_stays'))->toHaveCount(1);
});
