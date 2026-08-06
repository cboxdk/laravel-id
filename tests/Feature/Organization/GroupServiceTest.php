<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Authorization\ValueObjects\ResourceRef;
use Cbox\Id\Organization\Contracts\Groups;
use Cbox\Id\Organization\Contracts\ResourceAccess;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Exceptions\GroupNameTaken;
use Cbox\Id\Organization\ValueObjects\GrantSubject;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('creates a group and manages its members through the relationship store', function (): void {
    $org = $this->makeOrganization();
    $groups = app(Groups::class);

    $group = $groups->create($org->id, 'Engineering');
    $groups->addMember($org->id, $group->id, 'user_1');
    $groups->addMember($org->id, $group->id, 'user_2');

    expect($groups->members($org->id, $group->id))->toBe(['user_1', 'user_2']);

    $groups->removeMember($org->id, $group->id, 'user_1');

    expect($groups->members($org->id, $group->id))->toBe(['user_2'])
        ->and($groups->groupsFor($org->id, 'user_2')->pluck('id')->all())->toBe([$group->id]);
});

it('refuses a duplicate group name within the organization', function (): void {
    $org = $this->makeOrganization();
    $groups = app(Groups::class);

    $groups->create($org->id, 'Engineering');

    expect(fn () => $groups->create($org->id, 'Engineering'))->toThrow(GroupNameTaken::class);
});

it('allows the same group name in different organizations', function (): void {
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B');
    $groups = app(Groups::class);

    $groups->create($a->id, 'Engineering');
    $group = $groups->create($b->id, 'Engineering');

    expect($group->organization_id)->toBe($b->id);
});

it('isolates groups and memberships between organizations', function (): void {
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B');
    $groups = app(Groups::class);

    $group = $this->makeGroup($a->id, 'Engineering', members: ['user_1']);

    expect($groups->forOrganization($b->id))->toHaveCount(0)
        ->and($groups->groupsFor($b->id, 'user_1'))->toHaveCount(0)
        ->and($groups->forOrganization($a->id)->pluck('id')->all())->toBe([$group->id]);
});

it('refuses adding a member to a group from another organization', function (): void {
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B');
    $group = $this->makeGroup($a->id, 'Engineering');

    expect(fn () => app(Groups::class)->addMember($b->id, $group->id, 'user_1'))
        ->toThrow(ModelNotFoundException::class);
});

it('deleting a group removes its memberships and every grant held through it', function (): void {
    $org = $this->makeOrganization();
    $groups = app(Groups::class);
    $access = app(ResourceAccess::class);
    $project = ResourceRef::of('project', 'p1');

    $group = $this->makeGroup($org->id, 'Engineering', members: ['user_1']);
    $access->grant($org->id, GrantSubject::group($group->id), MembershipRole::Developer, $project);

    expect($this->effectiveRole($org->id, 'user_1', $project))->toBe(MembershipRole::Developer);

    $groups->delete($org->id, $group->id);

    // No dangling access: the grant died with the group.
    expect($this->effectiveRole($org->id, 'user_1', $project))->toBeNull()
        ->and($access->grantsOn($org->id, $project))->toBe([]);
});
