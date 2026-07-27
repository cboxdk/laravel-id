<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

/**
 * The package's actual first-run experience.
 *
 * Its own suite is not one: `TestCase::defineDatabaseMigrations()` publishes THIS
 * package's optional users migration instead of Laravel's, so the schema the suite
 * migrates against has never contained the tables a stock `laravel new` ships. That
 * blind spot hid a hard failure — the package created a `password_reset_tokens`
 * table, and so does Laravel's own `0001_01_01_000000_create_users_table` skeleton
 * migration, which sorts first and is present in every scaffolded app. Every
 * greenfield `composer require cboxdk/laravel-id && php artisan migrate` died on
 * "table already exists", on every engine.
 *
 * So this test builds the missing case: a second connection carrying Laravel's
 * stock skeleton tables verbatim, then the package's entire migration set — every
 * path registered with the migrator, in the order a real `php artisan migrate`
 * would run them — on top.
 */

/**
 * An empty database the migrator can be pointed at, independent of the one the
 * suite itself runs on.
 *
 * On PostgreSQL — what production runs, and the engine where the rename actually
 * has to move indexes and a unique constraint with the table — that is a throwaway
 * SCHEMA on the same server, so no CREATE DATABASE privilege is needed and the
 * `engines` CI job covers the real thing. Everywhere else it is a temporary sqlite
 * file: the collision this guards is a property of migration FILE NAMES and table
 * names, which no engine changes.
 *
 * @return array{0: string, 1: Closure(): void} [connection name, cleanup]
 */
function greenfieldConnection(): array
{
    /** @var array<string, mixed> $base */
    $base = config('database.connections.testing');

    if (($base['driver'] ?? null) === 'pgsql') {
        $schema = 'greenfield_'.Str::lower(Str::random(12));

        config()->set('database.connections.greenfield', array_merge($base, ['search_path' => $schema]));
        DB::purge('greenfield');

        // Created THROUGH the greenfield connection, not the suite's: on a server
        // engine each test runs inside a transaction, and a schema created there
        // would be invisible to any other connection until it committed. Postgres
        // accepts a `search_path` naming a schema that does not exist yet, so the
        // connection can bootstrap its own.
        DB::connection('greenfield')->statement('create schema "'.$schema.'"');

        return ['greenfield', function () use ($schema): void {
            DB::connection('greenfield')->statement('drop schema "'.$schema.'" cascade');
            DB::purge('greenfield');
        }];
    }

    $file = tempnam(sys_get_temp_dir(), 'cbox-id-greenfield').'.sqlite';
    touch($file);

    config()->set('database.connections.greenfield', [
        'driver' => 'sqlite',
        'database' => $file,
        'prefix' => '',
        'foreign_key_constraints' => true,
    ]);

    DB::purge('greenfield');

    return ['greenfield', function () use ($file): void {
        DB::purge('greenfield');
        @unlink($file);
    }];
}

/**
 * Laravel's `0001_01_01_000000_create_users_table` skeleton migration, verbatim.
 * Reproduced rather than referenced because the framework ships it as a stub inside
 * the application skeleton, not as anything a package can load.
 */
function migrateLaravelSkeleton(string $connection): void
{
    $schema = Schema::connection($connection);

    $schema->create('users', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->string('email')->unique();
        $table->timestamp('email_verified_at')->nullable();
        $table->string('password');
        $table->rememberToken();
        $table->timestamps();
    });

    $schema->create('password_reset_tokens', function (Blueprint $table): void {
        $table->string('email')->primary();
        $table->string('token');
        $table->timestamp('created_at')->nullable();
    });

    $schema->create('sessions', function (Blueprint $table): void {
        $table->string('id')->primary();
        $table->foreignId('user_id')->nullable()->index();
        $table->string('ip_address', 45)->nullable();
        $table->text('user_agent')->nullable();
        $table->longText('payload');
        $table->integer('last_activity')->index();
    });
}

it('migrates green on a stock Laravel app that still has its skeleton migrations', function (): void {
    [$connection, $cleanup] = greenfieldConnection();

    migrateLaravelSkeleton($connection);

    $exit = Artisan::call('migrate', ['--database' => $connection, '--force' => true]);

    $output = Artisan::output();

    expect($exit)->toBe(0, 'php artisan migrate failed on a stock Laravel schema: '.$output);

    $schema = Schema::connection($connection);

    // The package's table exists under its own name...
    expect($schema->hasTable('cbox_id_password_reset_tokens'))->toBeTrue()
        ->and($schema->hasColumn('cbox_id_password_reset_tokens', 'token_hash'))->toBeTrue()
        ->and($schema->hasColumn('cbox_id_password_reset_tokens', 'environment_id'))->toBeTrue();

    // ...and Laravel's is still Laravel's: same shape, untouched. The rename
    // migration must never adopt, reshape or drop a table it did not create.
    expect($schema->hasTable('password_reset_tokens'))->toBeTrue()
        ->and($schema->hasColumn('password_reset_tokens', 'token'))->toBeTrue()
        ->and($schema->hasColumn('password_reset_tokens', 'token_hash'))->toBeFalse();

    $cleanup();
});

/**
 * The upgrade path. A database that is already through v0.62.0 holds the package's
 * rows under the OLD name; the rename has to carry them across rather than start a
 * fresh empty table.
 */
it('carries an existing installation across the rename with its rows', function (): void {
    [$connection, $cleanup] = greenfieldConnection();

    $schema = Schema::connection($connection);

    // The v0.62.0 shape, under the old name.
    $schema->create('password_reset_tokens', function (Blueprint $table): void {
        $table->string('id', 26)->primary();
        $table->string('environment_id', 26)->index();
        $table->string('email')->index();
        $table->string('token_hash')->unique();
        $table->timestamp('expires_at');
        $table->timestamp('consumed_at')->nullable();
        $table->timestamps();
    });

    DB::connection($connection)->table('password_reset_tokens')->insert([
        'id' => '01JQEXISTINGROWXXXXXXXXXXX',
        'environment_id' => 'env_test',
        'email' => 'someone@example.com',
        'token_hash' => str_repeat('a', 64),
        'expires_at' => '2030-01-01 00:00:00',
        'consumed_at' => null,
        'created_at' => '2026-01-01 00:00:00',
        'updated_at' => '2026-01-01 00:00:00',
    ]);

    // Pretend the create migration already ran, exactly as it would have on a
    // v0.62.0 database — otherwise the migrator would try to create the table again.
    $schema->create('migrations', function (Blueprint $table): void {
        $table->increments('id');
        $table->string('migration');
        $table->integer('batch');
    });

    DB::connection($connection)->table('migrations')->insert([
        'migration' => '2026_01_01_001600_create_credential_token_tables',
        'batch' => 1,
    ]);

    // email_verification_tokens is created by that same (now-skipped) migration.
    $schema->create('email_verification_tokens', function (Blueprint $table): void {
        $table->string('id', 26)->primary();
        $table->string('environment_id', 26)->index();
        $table->string('user_id')->index();
        $table->string('email');
        $table->string('token_hash')->unique();
        $table->timestamp('expires_at');
        $table->timestamp('consumed_at')->nullable();
        $table->timestamps();
    });

    $exit = Artisan::call('migrate', ['--database' => $connection, '--force' => true]);
    $output = Artisan::output();

    expect($exit)->toBe(0, 'php artisan migrate failed on an existing installation: '.$output);

    expect($schema->hasTable('cbox_id_password_reset_tokens'))->toBeTrue()
        ->and($schema->hasTable('password_reset_tokens'))->toBeFalse();

    $row = DB::connection($connection)->table('cbox_id_password_reset_tokens')->first();

    expect($row)->not->toBeNull()
        ->and($row->email)->toBe('someone@example.com')
        ->and($row->token_hash)->toBe(str_repeat('a', 64));

    // Replaying is a no-op, not a second rename.
    expect(Artisan::call('migrate', ['--database' => $connection, '--force' => true]))->toBe(0);

    $cleanup();
});
