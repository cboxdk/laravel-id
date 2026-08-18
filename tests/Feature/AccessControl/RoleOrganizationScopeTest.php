<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Exceptions\UnknownRole;
use Cbox\Id\AccessControl\Models\Permission;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * THE TENANT FENCE AS A QUERY, NOT A CONVENTION.
 *
 * The role lifecycle resolved by primary key under the environment scope and nothing
 * else, which made the organization boundary something every caller had to remember. A
 * surface that correctly checked "may this administrator manage organization A" and then
 * passed an id belonging to organization B mutated B's role — nothing between the check
 * and the write ever compared the two.
 *
 * Nothing shipped was exploitable: the console resolves through an ownership-scoped set
 * before it calls. But this is a package with more than one consumer, and a contract that
 * invites the mistake is a contract that will eventually get it.
 *
 * The parameter is optional, and null still means the environment plane — an operator
 * managing the environment's own roles, which is exactly what its absence has always
 * meant. Existing callers are unmoved; the fence is there for anyone who asks for it.
 */
it('refuses to update a role belonging to another organization', function (): void {
    $mine = app(Roles::class)->define('org_a', 'Editor');

    expect(fn () => app(Roles::class)->updateRole($mine->id, 'Renamed', null, 'org_b'))
        ->toThrow(UnknownRole::class);
})->group('security');

it('refuses to delete another organization’s role', function (): void {
    $mine = app(Roles::class)->define('org_a', 'Editor');

    expect(fn () => app(Roles::class)->deleteRole($mine->id, 'org_b'))
        ->toThrow(UnknownRole::class);
})->group('security');

it('refuses to attach a permission to another organization’s role', function (): void {
    $mine = app(Roles::class)->define('org_a', 'Editor');
    // grantPermission() has always taken the organization and fenced on it — its own
    // comment says "never grant onto another tenant's role". This is the same fence, on
    // the four methods that did not get it.
    app(Roles::class)->grantPermission('org_a', $mine->id, 'invoices:create');
    $permission = Permission::query()->where('name', 'invoices:create')->firstOrFail();

    expect(fn () => app(Roles::class)->attachPermission($mine->id, $permission->id, 'org_b'))
        ->toThrow(UnknownRole::class);
})->group('security');

it('still does the work for the organization that owns the role', function (): void {
    // The positive control: a fence that refuses everybody passes all three above.
    $mine = app(Roles::class)->define('org_a', 'Editor');

    $updated = app(Roles::class)->updateRole($mine->id, 'Renamed', null, 'org_a');

    expect($updated->name)->toBe('Renamed');
})->group('security');

it('leaves a caller that names no organization exactly as scoped as it was', function (): void {
    // Null is the environment plane, and the absence of the argument has always meant
    // this. Existing callers must not change behaviour because the parameter now exists.
    $mine = app(Roles::class)->define('org_a', 'Editor');

    expect(app(Roles::class)->updateRole($mine->id, 'Renamed')->name)->toBe('Renamed');
})->group('security');
