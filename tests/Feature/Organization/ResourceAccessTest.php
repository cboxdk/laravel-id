<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Authorization\ValueObjects\ResourceRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\Subject;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\ResourceAccess;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\ValueObjects\GrantSubject;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('resolves no access for a stranger (deny-by-default)', function (): void {
    $org = $this->makeOrganization();

    expect($this->effectiveRole($org->id, 'user_stranger'))->toBeNull()
        ->and($this->effectiveRole($org->id, 'user_stranger', ResourceRef::of('project', 'p1')))->toBeNull();
});

it('resolves the membership role as the org-level effective role', function (): void {
    $org = $this->makeOrganization();
    app(Memberships::class)->add($org->id, 'user_1', 'developer');

    expect($this->effectiveRole($org->id, 'user_1'))->toBe(MembershipRole::Developer);
});

it('a direct resource grant raises the effective role above the membership', function (): void {
    $org = $this->makeOrganization();
    app(Memberships::class)->add($org->id, 'user_1', 'viewer');
    $project = ResourceRef::of('project', 'p1');

    $this->grantAccess($org->id, GrantSubject::user('user_1'), MembershipRole::Admin, $project);

    // Org-level: still viewer. On the project: admin wins.
    expect($this->effectiveRole($org->id, 'user_1'))->toBe(MembershipRole::Viewer)
        ->and($this->effectiveRole($org->id, 'user_1', $project))->toBe(MembershipRole::Admin);
});

it('a grant never lowers the effective role (highest wins)', function (): void {
    $org = $this->makeOrganization();
    app(Memberships::class)->add($org->id, 'user_1', 'admin');
    $project = ResourceRef::of('project', 'p1');

    $this->grantAccess($org->id, GrantSubject::user('user_1'), MembershipRole::Viewer, $project);

    expect($this->effectiveRole($org->id, 'user_1', $project))->toBe(MembershipRole::Admin);
});

it('resolves group-inherited grants and picks the highest across sources', function (): void {
    $org = $this->makeOrganization();
    app(Memberships::class)->add($org->id, 'user_1', 'viewer');
    $project = ResourceRef::of('project', 'p1');
    $service = ResourceRef::of('service', 's1');

    $group = $this->makeGroup($org->id, 'Engineering', members: ['user_1']);
    $this->grantAccess($org->id, GrantSubject::group($group->id), MembershipRole::Developer, $project);
    $this->grantAccess($org->id, GrantSubject::user('user_1'), MembershipRole::Member, $service);

    expect($this->effectiveRole($org->id, 'user_1', $project))->toBe(MembershipRole::Developer)
        ->and($this->effectiveRole($org->id, 'user_1', $service))->toBe(MembershipRole::Member)
        ->and($this->effectiveRole($org->id, 'user_1', $project, $service))->toBe(MembershipRole::Developer);
});

it('a suspended membership confers no access', function (): void {
    $org = $this->makeOrganization();
    $memberships = app(Memberships::class);
    $membership = $memberships->add($org->id, 'user_1', 'admin');

    $membership->forceFill(['status' => 'suspended'])->save();

    expect($this->effectiveRole($org->id, 'user_1'))->toBeNull();
});

it('answers grant checks through the raw PDP path with group expansion', function (): void {
    $org = $this->makeOrganization();
    $project = ResourceRef::of('project', 'p1');
    $group = $this->makeGroup($org->id, 'Engineering', members: ['user_1']);

    $this->grantAccess($org->id, GrantSubject::group($group->id), MembershipRole::Developer, $project);

    // Grants are plain relationship tuples, so the boolean PDP resolves them —
    // including through the group userset — with no extra wiring.
    expect($this->pdp()->can($org->id, Subject::user('user_1'), 'developer', $project))->toBeTrue()
        ->and($this->pdp()->can($org->id, Subject::user('user_2'), 'developer', $project))->toBeFalse();
});

it('revoking a grant removes exactly that grant', function (): void {
    $org = $this->makeOrganization();
    $access = app(ResourceAccess::class);
    $project = ResourceRef::of('project', 'p1');

    $access->grant($org->id, GrantSubject::user('user_1'), MembershipRole::Developer, $project);
    $access->grant($org->id, GrantSubject::user('user_2'), MembershipRole::Viewer, $project);

    $access->revoke($org->id, GrantSubject::user('user_1'), MembershipRole::Developer, $project);

    expect($this->effectiveRole($org->id, 'user_1', $project))->toBeNull()
        ->and($this->effectiveRole($org->id, 'user_2', $project))->toBe(MembershipRole::Viewer);
});

it('lists grants on a resource for admin surfaces', function (): void {
    $org = $this->makeOrganization();
    $access = app(ResourceAccess::class);
    $project = ResourceRef::of('project', 'p1');
    $group = $this->makeGroup($org->id, 'Engineering');

    $access->grant($org->id, GrantSubject::group($group->id), MembershipRole::Developer, $project);
    $access->grant($org->id, GrantSubject::user('user_1'), MembershipRole::Admin, $project);

    $grants = $access->grantsOn($org->id, $project);

    expect($grants)->toHaveCount(2)
        ->and($grants[0]->subject->type)->toBe('user')
        ->and($grants[0]->role)->toBe(MembershipRole::Admin)
        ->and($grants[1]->subject->isGroup())->toBeTrue()
        ->and($grants[1]->role)->toBe(MembershipRole::Developer);
});

it('refuses a grant to a group that does not exist in the organization', function (): void {
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B');
    $group = $this->makeGroup($a->id, 'Engineering');

    expect(fn () => $this->grantAccess($b->id, GrantSubject::group($group->id), MembershipRole::Developer, ResourceRef::of('project', 'p1')))
        ->toThrow(ModelNotFoundException::class);
});

it('isolates grants between organizations', function (): void {
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B');
    $project = ResourceRef::of('project', 'p1');

    $this->grantAccess($a->id, GrantSubject::user('user_1'), MembershipRole::Admin, $project);

    expect($this->effectiveRole($b->id, 'user_1', $project))->toBeNull();
});
