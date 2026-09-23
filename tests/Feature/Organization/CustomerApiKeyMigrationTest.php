<?php

declare(strict_types=1);

use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Contracts\UserApiTokens;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Enums\OrganizationType;
use Cbox\Id\Organization\Enums\TokenScope;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Cbox\Id\Organization\ValueObjects\ResourceFamilies;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

/**
 * The migration that binds user API tokens to an app changes three columns of a table
 * that already holds live credentials. What matters is the OUTCOME for those rows: a
 * personal token written under the old schema must come through the column changes —
 * a table rebuild on SQLite — still resolvable, with its scope and families intact.
 */
it('carries a personal token written under the old schema across, still working', function (): void {
    $migration = require __DIR__.'/../../../database/migrations/2026_09_24_000100_bind_user_api_tokens_to_an_app.php';

    $org = app(Organizations::class)->create(new NewOrganization(
        name: 'Acme',
        slug: 'acme-'.Str::lower(Str::random(6)),
        type: OrganizationType::Customer,
    ));
    app(Memberships::class)->add($org->id, 'user_old', MembershipRole::Admin);

    $migration->down();

    expect(Schema::hasColumn('user_api_tokens', 'client_id'))->toBeFalse();

    // Written the way the pre-migration service wrote it.
    $plaintext = 'cbid_pat_'.Str::random(48);
    DB::table('user_api_tokens')->insert([
        'id' => (string) Str::ulid(),
        'environment_id' => 'env_test',
        'organization_id' => $org->id,
        'user_id' => 'user_old',
        'name' => 'Deploy bot',
        'prefix' => substr($plaintext, 0, 12),
        'token_hash' => hash('sha256', $plaintext),
        'scope' => 'write',
        'resource_families' => json_encode(['services']),
        'expires_at' => now()->addDays(30),
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    $migration->up();

    $token = app(UserApiTokens::class)->resolve($plaintext);

    expect($token)->not->toBeNull()
        ->and($token?->scope)->toBe(TokenScope::Write)
        ->and($token?->name)->toBe('Deploy bot')
        ->and($token?->resource_families->toStorage())->toBe(['services'])
        ->and(DB::table('user_api_tokens')->whereNotNull('client_id')->count())->toBe(0);

    // The unique hash index survived the rebuild (asked of the schema, not by provoking a
    // violation: DDL above has already ended MySQL's test transaction, so there is no
    // savepoint left to recover a refused insert into).
    $uniqueOnHash = collect(Schema::getIndexes('user_api_tokens'))
        ->contains(fn (array $index): bool => $index['unique'] && $index['columns'] === ['token_hash']);

    expect($uniqueOnHash)->toBeTrue();

    // And a token issued afterwards goes through the new schema unchanged.
    $fresh = app(UserApiTokens::class)->issue($org->id, 'user_old', 'CLI', TokenScope::Read, ResourceFamilies::none());

    expect(app(UserApiTokens::class)->resolve($fresh->plaintext)?->id)->toBe($fresh->token->id);
});
