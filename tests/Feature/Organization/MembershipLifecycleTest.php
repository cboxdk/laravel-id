<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantContext;
use Cbox\Id\Kernel\Tenancy\GenericTenant;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Enums\MembershipStatus;
use Cbox\Id\Organization\Enums\OrganizationStatus;
use Cbox\Id\Organization\Enums\OwnershipTransferRefusal;
use Cbox\Id\Organization\Exceptions\LastOwner;
use Cbox\Id\Organization\Exceptions\NotOrganizationOwner;
use Cbox\Id\Organization\Exceptions\OwnershipTransferRefused;
use Cbox\Id\Organization\Models\Membership;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/** Put a membership into a non-active state, as an invitation flow or a suspension would. */
function setMembershipStatus(string $organizationId, string $userId, MembershipStatus $status): void
{
    app(TenantContext::class)->runAs(GenericTenant::of($organizationId), function () use ($userId, $status): void {
        Membership::query()->where('user_id', $userId)->firstOrFail()->update(['status' => $status]);
    });
}

/** Catch the refusal so its reason and wording can be asserted, not just its class. */
function refusalOf(Closure $call): Throwable
{
    try {
        $call();
    } catch (Throwable $e) {
        return $e;
    }

    throw new RuntimeException('Expected the call to be refused, but it succeeded.');
}

// ---------------------------------------------------------------- leave

it('lets a member leave, taking their grants with them', function (): void {
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();
    $org = $this->makeOrganization();
    $memberships = app(Memberships::class);
    $memberships->add($org->id, 'owner', MembershipRole::Owner);
    $memberships->add($org->id, 'bob', MembershipRole::Member);

    $role = app(Roles::class)->define($org->id, 'Editor');
    app(Roles::class)->assign($org->id, 'bob', $role->id);

    $memberships->leave($org->id, 'bob');

    expect($memberships->of($org->id, 'bob'))->toBeNull()
        ->and(app(Roles::class)->assignmentsForSubject($org->id, 'bob'))->toBe([]);

    $events->assertEmitted('membership.deleted', fn (DomainEvent $e): bool => $e->payload['reason'] === 'left'
        && $e->payload['role'] === 'member'
        && $e->payload['user_id'] === 'bob'
        && $e->organizationId === $org->id);
    // The legacy event still fires: provisioning deprovisions on it.
    $events->assertEmitted('organization.member_removed');
    // Attributed to the person who left, not to "the system".
    $audit->assertRecorded('organization.member_removed', fn (AuditEvent $e): bool => $e->actorType === ActorType::User && $e->actorId === 'bob');
});

it('refuses to let the only owner leave, and says what to do instead', function (): void {
    $org = $this->makeOrganization();
    $memberships = app(Memberships::class);
    $memberships->add($org->id, 'owner', MembershipRole::Owner);
    $memberships->add($org->id, 'bob', MembershipRole::Admin);

    $refusal = refusalOf(fn () => $memberships->leave($org->id, 'owner'));

    expect($refusal)->toBeInstanceOf(LastOwner::class)
        ->and($refusal->getMessage())->toContain('only owner')
        ->and($refusal->getMessage())->toContain('Transfer ownership')
        ->and($memberships->activeRole($org->id, 'owner'))->toBe(MembershipRole::Owner);
});

it('lets an owner leave while another owner remains', function (): void {
    $org = $this->makeOrganization();
    $memberships = app(Memberships::class);
    $memberships->add($org->id, 'owner_1', MembershipRole::Owner);
    $memberships->add($org->id, 'owner_2', MembershipRole::Owner);

    $memberships->leave($org->id, 'owner_1');

    expect($memberships->owners($org->id))->toBe(['owner_2']);
});

it('treats leaving an organization you are not in as already done', function (): void {
    $events = $this->fakeEvents();
    $org = $this->makeOrganization();
    $events->emitted = [];

    app(Memberships::class)->leave($org->id, 'stranger');

    $events->assertNothingEmitted();
});

// ---------------------------------------------------------------- transfer

it('transfers ownership to an existing member and keeps the previous owner as admin', function (): void {
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();
    $org = $this->makeOrganization();
    $memberships = app(Memberships::class);
    $memberships->add($org->id, 'alice', MembershipRole::Owner);
    $memberships->add($org->id, 'bob', MembershipRole::Developer);

    $newOwner = $memberships->transferOwnership($org->id, 'alice', 'bob');

    expect($newOwner->user_id)->toBe('bob')
        ->and($newOwner->role)->toBe(MembershipRole::Owner)
        ->and($memberships->activeRole($org->id, 'bob'))->toBe(MembershipRole::Owner)
        ->and($memberships->activeRole($org->id, 'alice'))->toBe(MembershipRole::Admin)
        ->and($memberships->owners($org->id))->toBe(['bob']);

    $events->assertEmitted('membership.updated', fn (DomainEvent $e): bool => $e->payload['user_id'] === 'bob'
        && $e->payload['role'] === 'owner'
        && $e->payload['previous_role'] === 'developer'
        && $e->payload['reason'] === 'ownership_transferred');
    $events->assertEmitted('membership.updated', fn (DomainEvent $e): bool => $e->payload['user_id'] === 'alice'
        && $e->payload['role'] === 'admin'
        && $e->payload['previous_role'] === 'owner');
    $audit->assertRecorded('organization.ownership_transferred', fn (AuditEvent $e): bool => $e->actorId === 'alice' && $e->targetId === 'bob');
});

it('refuses a transfer from somebody who is not an active owner', function (): void {
    $org = $this->makeOrganization();
    $memberships = app(Memberships::class);
    $memberships->add($org->id, 'alice', MembershipRole::Owner);
    $memberships->add($org->id, 'mallory', MembershipRole::Admin);
    $memberships->add($org->id, 'bob', MembershipRole::Member);

    // An admin cannot give away what they do not hold.
    $refusal = refusalOf(fn () => $memberships->transferOwnership($org->id, 'mallory', 'bob'));

    expect($refusal)->toBeInstanceOf(OwnershipTransferRefused::class)
        ->and($refusal instanceof OwnershipTransferRefused ? $refusal->reason : null)->toBe(OwnershipTransferRefusal::NotOwner)
        ->and($memberships->owners($org->id))->toBe(['alice'])
        ->and($memberships->activeRole($org->id, 'bob'))->toBe(MembershipRole::Member);

    // Nor can a SUSPENDED owner.
    $memberships->add($org->id, 'carol', MembershipRole::Owner);
    setMembershipStatus($org->id, 'carol', MembershipStatus::Suspended);

    $suspended = refusalOf(fn () => $memberships->transferOwnership($org->id, 'carol', 'bob'));
    expect($suspended instanceof OwnershipTransferRefused ? $suspended->reason : null)->toBe(OwnershipTransferRefusal::NotOwner);
});

it('refuses a transfer to somebody who is not a member of THIS organization', function (): void {
    $org = $this->makeOrganization('A');
    $other = $this->makeOrganization('B');
    $memberships = app(Memberships::class);
    $memberships->add($org->id, 'alice', MembershipRole::Owner);
    // Bob is a member — of a different organization.
    $memberships->add($other->id, 'bob', MembershipRole::Member);

    $refusal = refusalOf(fn () => $memberships->transferOwnership($org->id, 'alice', 'bob'));

    expect($refusal instanceof OwnershipTransferRefused ? $refusal->reason : null)->toBe(OwnershipTransferRefusal::TargetNotMember)
        ->and($refusal->getMessage())->toContain('not a member')
        ->and($memberships->owners($org->id))->toBe(['alice'])
        ->and($memberships->of($org->id, 'bob'))->toBeNull();
});

it('refuses a transfer to a member who is not active', function (): void {
    $org = $this->makeOrganization();
    $memberships = app(Memberships::class);
    $memberships->add($org->id, 'alice', MembershipRole::Owner);
    $memberships->add($org->id, 'bob', MembershipRole::Member);
    setMembershipStatus($org->id, 'bob', MembershipStatus::Suspended);

    $refusal = refusalOf(fn () => $memberships->transferOwnership($org->id, 'alice', 'bob'));

    expect($refusal instanceof OwnershipTransferRefused ? $refusal->reason : null)->toBe(OwnershipTransferRefusal::TargetNotActive)
        ->and($memberships->owners($org->id))->toBe(['alice']);
});

it('refuses a transfer to the owner themselves', function (): void {
    $org = $this->makeOrganization();
    app(Memberships::class)->add($org->id, 'alice', MembershipRole::Owner);

    $refusal = refusalOf(fn () => app(Memberships::class)->transferOwnership($org->id, 'alice', 'alice'));

    expect($refusal instanceof OwnershipTransferRefused ? $refusal->reason : null)->toBe(OwnershipTransferRefusal::SameMember)
        ->and(app(Memberships::class)->activeRole($org->id, 'alice'))->toBe(MembershipRole::Owner);
});

/**
 * The transfer is atomic against a concurrent remove/leave/changeRole only because it takes
 * both rows under a lock. Sqlite compiles no FOR UPDATE, so this runs on the engine suites.
 */
it('compiles the transfer read with FOR UPDATE on a server engine', function (): void {
    $org = $this->makeOrganization();
    $memberships = app(Memberships::class);
    $memberships->add($org->id, 'alice', MembershipRole::Owner);
    $memberships->add($org->id, 'bob', MembershipRole::Member);

    $sql = [];
    DB::listen(function ($query) use (&$sql): void {
        $sql[] = strtolower($query->sql);
    });

    $memberships->transferOwnership($org->id, 'alice', 'bob');

    $locking = array_filter($sql, fn (string $s): bool => str_contains($s, 'memberships')
        && str_contains($s, 'user_id')
        && str_contains($s, ' in (')
        && str_contains($s, 'for update'));

    expect($locking)->toHaveCount(1);
})->skip(fn (): bool => DB::connection()->getDriverName() === 'sqlite', 'SQLite has no row locks to compile.');

// ---------------------------------------------------------------- single-owner helpers

it('answers the active tier only while the membership is active', function (): void {
    $org = $this->makeOrganization();
    $memberships = app(Memberships::class);
    $memberships->add($org->id, 'alice', MembershipRole::Admin);

    expect($memberships->activeRole($org->id, 'alice'))->toBe(MembershipRole::Admin)
        ->and($memberships->activeRole($org->id, 'nobody'))->toBeNull();

    setMembershipStatus($org->id, 'alice', MembershipStatus::Suspended);

    expect($memberships->activeRole($org->id, 'alice'))->toBeNull();
});

it('never lets Owner be handed out directly', function (): void {
    expect(MembershipRole::Owner->isAssignable())->toBeFalse();

    foreach (MembershipRole::assignable() as $role) {
        expect($role->isAssignable())->toBeTrue();
    }
});

// ---------------------------------------------------------------- owner archives

it('lets the owner archive their own organization', function (): void {
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();
    $org = $this->makeOrganization();
    app(Memberships::class)->add($org->id, 'alice', MembershipRole::Owner);

    $archived = app(Organizations::class)->archiveAsOwner($org->id, 'alice');

    expect($archived->status)->toBe(OrganizationStatus::Deleted);
    $events->assertEmitted('organization.archived');
    $events->assertEmitted('organization.deleted', fn (DomainEvent $e): bool => $e->payload['id'] === $org->id);
    $audit->assertRecorded('organization.archived', fn (AuditEvent $e): bool => $e->actorType === ActorType::User && $e->actorId === 'alice');

    // Idempotent, like the operator's archive.
    $events->emitted = [];
    app(Organizations::class)->archiveAsOwner($org->id, 'alice');
    $events->assertNothingEmitted();
});

it('refuses an archive from a member who is not the owner', function (): void {
    $org = $this->makeOrganization();
    app(Memberships::class)->add($org->id, 'alice', MembershipRole::Owner);
    app(Memberships::class)->add($org->id, 'bob', MembershipRole::Admin);

    $refusal = refusalOf(fn () => app(Organizations::class)->archiveAsOwner($org->id, 'bob'));

    expect($refusal)->toBeInstanceOf(NotOrganizationOwner::class)
        ->and($refusal->getMessage())->toContain('not an active owner')
        ->and(app(Organizations::class)->find($org->id)?->status)->toBe(OrganizationStatus::Active);
});

it('refuses the owner of ANOTHER organization even with tenant scoping suspended', function (): void {
    // The owner check is bound in the WHERE clause, not left to the tenant scope. With the
    // scope suspended — a provisioning job, a backfill — a scope-only check would find
    // Mallory's owner row in her own organization and let her archive this one.
    $victim = $this->makeOrganization('Victim');
    $own = $this->makeOrganization('Own');
    app(Memberships::class)->add($victim->id, 'alice', MembershipRole::Owner);
    app(Memberships::class)->add($own->id, 'mallory', MembershipRole::Owner);

    $refusal = refusalOf(fn () => app(TenantContext::class)->withoutScope(
        fn () => app(Organizations::class)->archiveAsOwner($victim->id, 'mallory'),
    ));

    expect($refusal)->toBeInstanceOf(NotOrganizationOwner::class)
        ->and(app(Organizations::class)->find($victim->id)?->status)->toBe(OrganizationStatus::Active);
});

// ---------------------------------------------------------------- with tenant scoping suspended
//
// Every lifecycle guard binds the organization in its WHERE clause rather than leaving it
// to the tenant scope. A guard behind a scoped query cannot fail while the scope is on, so
// these run with it OFF — the state a provisioning job or backfill runs in.

it('does not promote a member of another organization when scoping is suspended', function (): void {
    $org = $this->makeOrganization('A');
    $other = $this->makeOrganization('B');
    $memberships = app(Memberships::class);
    $memberships->add($org->id, 'alice', MembershipRole::Owner);
    $memberships->add($other->id, 'bob', MembershipRole::Member);

    $refusal = refusalOf(fn () => app(TenantContext::class)->withoutScope(
        fn () => $memberships->transferOwnership($org->id, 'alice', 'bob'),
    ));

    expect($refusal instanceof OwnershipTransferRefused ? $refusal->reason : null)->toBe(OwnershipTransferRefusal::TargetNotMember)
        ->and($memberships->activeRole($other->id, 'bob'))->toBe(MembershipRole::Member)
        ->and($memberships->activeRole($org->id, 'alice'))->toBe(MembershipRole::Owner);
});

it('leaves only the named organization when scoping is suspended', function (): void {
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B');
    $memberships = app(Memberships::class);
    $memberships->add($a->id, 'owner', MembershipRole::Owner);
    $memberships->add($b->id, 'owner', MembershipRole::Owner);
    $memberships->add($a->id, 'bob', MembershipRole::Member);
    $memberships->add($b->id, 'bob', MembershipRole::Member);

    app(TenantContext::class)->withoutScope(fn () => $memberships->leave($a->id, 'bob'));

    expect($memberships->of($a->id, 'bob'))->toBeNull()
        ->and($memberships->activeRole($b->id, 'bob'))->toBe(MembershipRole::Member);
});

it('removes the person from the named organization only when scoping is suspended', function (): void {
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B');
    $memberships = app(Memberships::class);
    $memberships->add($a->id, 'bob', MembershipRole::Member);
    $memberships->add($b->id, 'bob', MembershipRole::Member);

    app(TenantContext::class)->withoutScope(fn () => $memberships->remove($a->id, 'bob'));

    expect($memberships->of($a->id, 'bob'))->toBeNull()
        ->and($memberships->activeRole($b->id, 'bob'))->toBe(MembershipRole::Member);
});

it('adds, reads and re-tiers the membership in the named organization only when scoping is suspended', function (): void {
    // Bob is already a member of B. Unbound, add() found THAT row and returned it without
    // adding him to A; of() answered with it; changeRole() re-tiered it.
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B');
    $memberships = app(Memberships::class);
    $memberships->add($b->id, 'bob', MembershipRole::Viewer);

    $suspended = fn (Closure $call) => app(TenantContext::class)->withoutScope($call);

    $added = $suspended(fn () => $memberships->add($a->id, 'bob', MembershipRole::Member));
    expect($added->organization_id)->toBe($a->id);

    expect($suspended(fn () => $memberships->of($a->id, 'bob'))?->organization_id)->toBe($a->id);

    $suspended(fn () => $memberships->changeRole($a->id, 'bob', MembershipRole::Admin));

    expect($memberships->activeRole($a->id, 'bob'))->toBe(MembershipRole::Admin)
        ->and($memberships->activeRole($b->id, 'bob'))->toBe(MembershipRole::Viewer);
});

it('still refuses demoting the last owner when scoping is suspended', function (): void {
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B');
    $memberships = app(Memberships::class);
    $memberships->add($a->id, 'alice', MembershipRole::Owner);
    $memberships->add($b->id, 'carol', MembershipRole::Owner);

    $refusal = refusalOf(fn () => app(TenantContext::class)->withoutScope(
        fn () => $memberships->changeRole($a->id, 'alice', MembershipRole::Admin),
    ));

    expect($refusal)->toBeInstanceOf(LastOwner::class)
        ->and($memberships->activeRole($a->id, 'alice'))->toBe(MembershipRole::Owner);
});

it('still refuses the last owner leaving when scoping is suspended', function (): void {
    // Unbound, the owner count would include B's owner and conclude A had two.
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B');
    $memberships = app(Memberships::class);
    $memberships->add($a->id, 'alice', MembershipRole::Owner);
    $memberships->add($b->id, 'carol', MembershipRole::Owner);

    $refusal = refusalOf(fn () => app(TenantContext::class)->withoutScope(fn () => $memberships->leave($a->id, 'alice')));

    expect($refusal)->toBeInstanceOf(LastOwner::class)
        ->and($refusal->getMessage())->toContain('only owner')
        ->and($memberships->owners($a->id))->toBe(['alice']);
});

it('answers the tier in THIS organization when scoping is suspended', function (): void {
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B');
    app(Memberships::class)->add($b->id, 'bob', MembershipRole::Owner);

    expect(app(TenantContext::class)->withoutScope(fn () => app(Memberships::class)->activeRole($a->id, 'bob')))->toBeNull();
});
