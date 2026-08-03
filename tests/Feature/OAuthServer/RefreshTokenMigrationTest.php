<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

/**
 * The columns that let a refreshed ID Token describe the ORIGINAL login, and the
 * rollback that removes them again.
 *
 * A `down()` nobody has ever run is a `down()` that does not work, and the one
 * time it is reached is the one time it has to — mid-incident, on a deployment
 * being rolled back for an unrelated reason. Dropping a column is also the
 * operation most likely to be silently unsupported by a driver, so it is proven
 * here rather than assumed from the fact that `up()` succeeded.
 */
it('adds the authentication columns, and takes them off again on rollback', function (): void {
    expect(Schema::hasColumn('oauth_refresh_tokens', 'auth_time'))->toBeTrue()
        ->and(Schema::hasColumn('oauth_refresh_tokens', 'amr'))->toBeTrue();

    $migration = require __DIR__.'/../../../database/migrations/2026_08_03_000200_remember_the_authentication_behind_a_refresh_token.php';

    $migration->down();

    expect(Schema::hasColumn('oauth_refresh_tokens', 'auth_time'))->toBeFalse()
        ->and(Schema::hasColumn('oauth_refresh_tokens', 'amr'))->toBeFalse();

    // And forward again, so a rollback is a step rather than a one-way door.
    $migration->up();

    expect(Schema::hasColumn('oauth_refresh_tokens', 'auth_time'))->toBeTrue()
        ->and(Schema::hasColumn('oauth_refresh_tokens', 'amr'))->toBeTrue();
});
