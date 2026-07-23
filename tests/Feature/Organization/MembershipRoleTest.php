<?php

declare(strict_types=1);

use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\MembershipRole;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('orders roles owner > admin > developer > member > viewer', function (): void {
    $ordered = [
        MembershipRole::Owner,
        MembershipRole::Admin,
        MembershipRole::Developer,
        MembershipRole::Member,
        MembershipRole::Viewer,
    ];

    foreach ($ordered as $i => $higher) {
        foreach (array_slice($ordered, $i + 1) as $lower) {
            expect($higher->outranks($lower))->toBeTrue()
                ->and($lower->outranks($higher))->toBeFalse();
        }
    }
});

it('a role never outranks itself', function (): void {
    foreach (MembershipRole::cases() as $role) {
        expect($role->outranks($role))->toBeFalse();
    }
});

it('limits organization management to owner and admin', function (): void {
    expect(MembershipRole::Owner->canManageOrganization())->toBeTrue()
        ->and(MembershipRole::Admin->canManageOrganization())->toBeTrue()
        ->and(MembershipRole::Developer->canManageOrganization())->toBeFalse()
        ->and(MembershipRole::Member->canManageOrganization())->toBeFalse()
        ->and(MembershipRole::Viewer->canManageOrganization())->toBeFalse();
});

it('denies write only to the read-only viewer', function (): void {
    expect(MembershipRole::Viewer->canWrite())->toBeFalse();

    foreach ([MembershipRole::Owner, MembershipRole::Admin, MembershipRole::Developer, MembershipRole::Member] as $role) {
        expect($role->canWrite())->toBeTrue();
    }
});

it('accepts the new roles on a membership', function (): void {
    $org = $this->makeOrganization();
    $memberships = app(Memberships::class);

    $developer = $memberships->add($org->id, 'user_dev', 'developer');
    $viewer = $memberships->add($org->id, 'user_view', 'viewer');

    expect($developer->role)->toBe(MembershipRole::Developer)
        ->and($viewer->role)->toBe(MembershipRole::Viewer);
});
