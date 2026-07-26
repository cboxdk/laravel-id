<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Enums\GrantSource;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Exceptions\LastOwner;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

it('adds a member scoped to the organization', function (): void {
    $org = $this->makeOrganization();
    $membership = app(Memberships::class)->add($org->id, 'user_1', MembershipRole::Admin);

    expect($membership->organization_id)->toBe($org->id)
        ->and($membership->role->value)->toBe('admin')
        ->and(app(Memberships::class)->of($org->id, 'user_1')?->id)->toBe($membership->id);
});

it('isolates memberships between organizations', function (): void {
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B');

    app(Memberships::class)->add($a->id, 'user_1', MembershipRole::Member);

    expect(app(Memberships::class)->of($b->id, 'user_1'))->toBeNull()
        ->and(app(Memberships::class)->of($a->id, 'user_1'))->not->toBeNull();
});

it('counts an organization\'s members with a single count query, not by hydrating them', function (): void {
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B');
    $memberships = app(Memberships::class);

    $memberships->add($a->id, 'user_1', MembershipRole::Member);
    $memberships->add($a->id, 'user_2', MembershipRole::Member);
    $memberships->add($b->id, 'user_3', MembershipRole::Member);

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

it('takes the role as an enum, so an unknown role cannot reach the contract at all', function (): void {
    // The role is authorization data. It used to be a `string` on the contract, so a
    // typo travelled all the way into the service and surfaced as an uncaught
    // ValueError (a 500) that PHPStan could not see. The contract now takes
    // MembershipRole: an unknown role is unrepresentable, and an untrusted string is
    // parsed at the edge where a bad value is a validation failure.
    $add = new ReflectionMethod(Memberships::class, 'add');
    $changeRole = new ReflectionMethod(Memberships::class, 'changeRole');

    expect((string) $add->getParameters()[2]->getType())->toBe(MembershipRole::class)
        ->and((string) $changeRole->getParameters()[2]->getType())->toBe(MembershipRole::class)
        // ...and the edge parse is the supported way in for untrusted input.
        ->and(MembershipRole::tryFrom('superuser'))->toBeNull()
        ->and(MembershipRole::tryFrom('Owner'))->toBeNull(); // case-sensitive: no fuzzy match
});

it('audits the role that was actually persisted', function (): void {
    // The audit payload used to record the caller's RAW string while the row stored the
    // parsed enum, so the trail could disagree with the stored value.
    $org = $this->makeOrganization();
    app(Memberships::class)->add($org->id, 'user_audit', MembershipRole::Admin);

    $entry = AuditEntry::query()->where('action', 'organization.member_added')->firstOrFail();

    expect($entry->context['role'] ?? null)
        ->toBe(app(Memberships::class)->of($org->id, 'user_audit')?->role->value);
});

it('changes a role and removes a member', function (): void {
    $org = $this->makeOrganization();
    $memberships = app(Memberships::class);

    $memberships->add($org->id, 'user_1', MembershipRole::Member);
    $memberships->changeRole($org->id, 'user_1', MembershipRole::Admin);
    expect($memberships->of($org->id, 'user_1')?->role?->value)->toBe('admin');

    $memberships->remove($org->id, 'user_1');
    expect($memberships->of($org->id, 'user_1'))->toBeNull();
});

it('lists members of an organization and organizations of a user', function (): void {
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B');
    $memberships = app(Memberships::class);

    $memberships->add($a->id, 'user_1', MembershipRole::Owner);
    $memberships->add($a->id, 'user_2', MembershipRole::Member);
    $memberships->add($b->id, 'user_1', MembershipRole::Admin);

    expect($memberships->forOrganization($a->id)->pluck('user_id')->all())->toEqualCanonicalizing(['user_1', 'user_2'])
        ->and($memberships->forOrganization($b->id))->toHaveCount(1)
        ->and($memberships->forUser('user_1')->pluck('organization_id')->all())->toEqualCanonicalizing([$a->id, $b->id])
        ->and($memberships->forUser('user_2'))->toHaveCount(1);
});

it('emits an event and records audit on member add', function (): void {
    $org = $this->makeOrganization();
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();

    app(Memberships::class)->add($org->id, 'user_1', MembershipRole::Member);

    $events->assertEmitted('organization.member_added');
    $audit->assertRecorded('organization.member_added');
});

it('refuses to demote or remove the sole owner', function (): void {
    $org = $this->makeOrganization();
    $memberships = app(Memberships::class);
    $memberships->add($org->id, 'owner_1', MembershipRole::Owner);
    $memberships->add($org->id, 'admin_1', MembershipRole::Admin);

    // The lone owner cannot be demoted or removed — it would orphan the org.
    expect(fn () => $memberships->changeRole($org->id, 'owner_1', MembershipRole::Member))
        ->toThrow(LastOwner::class)
        ->and(fn () => $memberships->remove($org->id, 'owner_1'))
        ->toThrow(LastOwner::class);

    // With a second owner present, either is allowed.
    $memberships->add($org->id, 'owner_2', MembershipRole::Owner);
    $memberships->changeRole($org->id, 'owner_1', MembershipRole::Member);
    expect($memberships->of($org->id, 'owner_1')?->role?->value)->toBe('member');
});

it('paginates an organization roster without hydrating every member', function (): void {
    $org = $this->makeOrganization();
    $memberships = app(Memberships::class);
    foreach (range(1, 5) as $i) {
        $memberships->add($org->id, "user_{$i}", MembershipRole::Member);
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

    $memberships->add($org->id, 'user_rbac', MembershipRole::Member);

    $role = $roles->define($org->id, 'billing-admin');
    $roles->assign($org->id, 'user_rbac', $role->id, GrantSource::Manual);

    expect($roles->assignmentsForSubject($org->id, 'user_rbac'))->toHaveCount(1);

    $memberships->remove($org->id, 'user_rbac');

    expect($roles->assignmentsForSubject($org->id, 'user_rbac'))->toBe([]);

    // Re-adding them starts from nothing, rather than restoring what was never re-granted.
    $memberships->add($org->id, 'user_rbac', MembershipRole::Member);
    expect($roles->assignmentsForSubject($org->id, 'user_rbac'))->toBe([]);
});

it('leaves another subject grants alone when one member is removed', function (): void {
    $org = $this->makeOrganization();
    $memberships = app(Memberships::class);
    $roles = app(Roles::class);

    $memberships->add($org->id, 'user_goes', MembershipRole::Member);
    $memberships->add($org->id, 'user_stays', MembershipRole::Member);

    $role = $roles->define($org->id, 'support');
    $roles->assign($org->id, 'user_goes', $role->id, GrantSource::Manual);
    $roles->assign($org->id, 'user_stays', $role->id, GrantSource::Manual);

    $memberships->remove($org->id, 'user_goes');

    expect($roles->assignmentsForSubject($org->id, 'user_goes'))->toBe([])
        ->and($roles->assignmentsForSubject($org->id, 'user_stays'))->toHaveCount(1);
});
