<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Organization\Enums\EnvironmentStatus;
use Cbox\Id\Organization\Enums\EnvironmentType;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\Contracts\Projects;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * An organization owns an IdP product outright — it is the only thing that can.
 *
 * `createForOrganization()` is the one writer, and `(organization_id, slug)` is the one
 * uniqueness rule. The pair of tests that asserted a project could still be owned from the
 * account side went with the account plane; what is left is the rule itself, which has to
 * hold per organization and not globally.
 *
 * ONE ASSERTION HERE WAS VACUOUS and is worth naming, because the shape recurs: this file
 * checked `$project->account_id` was null long after the column was deleted. Eloquent
 * answers null for an attribute a model does not have, so it passed for the wrong reason —
 * and phpstan analyses `src` and `tests/Fixtures`, not the suite, so nothing caught it. A
 * deleted column can only be asserted about through the schema, never through a model.
 */
beforeEach(function (): void {
    Environment::query()->create([
        'name' => 'Platform',
        'slug' => 'platform-'.Str::ulid(),
        'type' => EnvironmentType::Production,
        'status' => EnvironmentStatus::Active,
        'is_default' => true,
        'settings' => [],
    ]);
});

it('creates a project the organization owns outright', function (): void {
    $organizationId = strtolower((string) Str::ulid());

    $project = app(Projects::class)->createForOrganization($organizationId, 'Standalone');

    expect($project->organization_id)->toBe($organizationId)
        ->and($project->slug)->toBe('standalone');

    // Asked of the SCHEMA, because that is the only place a column's absence is a fact.
    // `$project->account_id` would answer null whether the column was dropped or merely
    // empty, which is how the assertion this replaces went on passing after the drop.
    expect(Schema::hasColumn('projects', 'account_id'))->toBeFalse();
});

it('finds it from the organization side', function (): void {
    $organizationId = strtolower((string) Str::ulid());
    app(Projects::class)->createForOrganization($organizationId, 'Standalone');

    $found = app(Projects::class)->forOrganization($organizationId);

    expect($found)->toHaveCount(1)
        ->and($found->first()?->name)->toBe('Standalone')
        // …and the ownership question answers yes for its owner and no for anyone else,
        // which is the read every authorization check in the console goes through.
        ->and(app(Projects::class)->ownedByOrganization((string) $found->first()?->id, $organizationId))->toBeTrue()
        ->and(app(Projects::class)->ownedByOrganization((string) $found->first()?->id, strtolower((string) Str::ulid())))->toBeFalse();
});

it('makes the second project of one name unique within the organization', function (): void {
    $organizationId = strtolower((string) Str::ulid());
    $projects = app(Projects::class);

    $projects->createForOrganization($organizationId, 'Default');
    $second = $projects->createForOrganization($organizationId, 'Default');

    // The slug loop has to scope to the same column the uniqueness key is on. It once
    // scoped to `account_id` while the key was `(organization_id, slug)`, found nothing,
    // and handed back 'default' twice — surfacing as a database error on an ordinary
    // "create a second project called Default".
    expect($second->slug)->toBe('default-2');
});

it('lets two organizations each have a default', function (): void {
    $projects = app(Projects::class);
    $first = strtolower((string) Str::ulid());
    $second = strtolower((string) Str::ulid());

    $projects->createForOrganization($first, 'Default');
    $other = $projects->createForOrganization($second, 'Default');

    // The other half of the same rule, and the one a too-eager global unique index breaks.
    expect($other->slug)->toBe('default');
});
