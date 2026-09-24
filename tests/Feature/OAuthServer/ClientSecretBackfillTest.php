<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Models\Client;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * THE OUTCOME OF THE BACKFILL, on rows that existed before it ran.
 *
 * A migration that creates the table and moves nothing passes every test that registers
 * its clients AFTER the upgrade — which is every other test in the suite. The client
 * that matters is the one already in production, holding a secret its deployment has
 * had for a year. So this puts clients in the database the way 1.18 left them — raw
 * rows, one `secret_hash` column, no secret table — runs the real migration over them,
 * and then authenticates with the plaintext they were issued.
 *
 * Runs on every engine the suite runs on (sqlite, PostgreSQL, MySQL).
 */
function legacyClientRow(string $environmentId, string $clientId, ?string $secretHash, string $type = 'confidential'): string
{
    $id = Str::lower((string) Str::ulid());

    DB::table('oauth_clients')->insert([
        'id' => $id,
        'environment_id' => $environmentId,
        'organization_id' => null,
        'client_id' => $clientId,
        'secret_hash' => $secretHash,
        'name' => 'Legacy '.$clientId,
        'type' => $type,
        'redirect_uris' => '[]',
        'grant_types' => json_encode(['client_credentials']),
        'scopes' => json_encode(['api.read']),
        'first_party' => false,
        'created_at' => now()->subYear(),
        'updated_at' => now()->subMonth(),
    ]);

    return $id;
}

it('moves every pre-existing secret into the secret table, and each still authenticates', function (): void {
    $migration = require __DIR__.'/../../../database/migrations/2026_09_24_000200_create_oauth_client_secrets_table.php';

    // The database as 1.18 left it: no secret table.
    $migration->down();
    expect(Schema::hasTable('oauth_client_secrets'))->toBeFalse();

    $plainA = 'csec_'.bin2hex(random_bytes(32));
    $plainC = 'csec_'.bin2hex(random_bytes(32));

    $ids = [
        'a' => legacyClientRow('env_test', 'cid_legacy_a', hash('sha256', $plainA)),
        'b' => legacyClientRow('env_test', 'cid_legacy_b', null, 'public'),
        'c' => legacyClientRow('env_other', 'cid_legacy_c', hash('sha256', $plainC)),
        'd' => legacyClientRow('env_test', 'cid_legacy_d', ''),
    ];

    try {
        $migration->up();

        $rows = DB::table('oauth_client_secrets')->whereIn('oauth_client_id', array_values($ids))->get()->keyBy('oauth_client_id');

        expect($rows)->toHaveCount(2)
            ->and($rows[$ids['a']]->secret_hash)->toBe(hash('sha256', $plainA))
            ->and($rows[$ids['a']]->environment_id)->toBe('env_test')
            ->and($rows[$ids['a']]->expires_at)->toBeNull()
            ->and($rows[$ids['a']]->hint)->toBeNull()
            ->and($rows[$ids['c']]->environment_id)->toBe('env_other')
            ->and($rows->has($ids['b']))->toBeFalse('a public client was given a secret')
            ->and($rows->has($ids['d']))->toBeFalse('an empty hash was moved as if it were a secret');

        // THE OUTCOME: the plaintext the client was issued before the upgrade still works,
        // through the registry and through the token endpoint.
        $a = Client::query()->findOrFail($ids['a']);
        $registry = app(ClientRegistry::class);

        expect($registry->verifySecret($a, $plainA))->toBeTrue()
            ->and($registry->verifySecret($a, $plainC))->toBeFalse();

        $this->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => 'cid_legacy_a',
            'client_secret' => $plainA,
        ])->assertOk();

        $this->runAsEnvironment('env_other', function () use ($ids, $registry, $plainC): void {
            $c = Client::query()->findOrFail($ids['c']);

            expect($registry->verifySecret($c, $plainC))->toBeTrue();
        });

        // Re-running moves nothing twice.
        $migration->up();

        expect(DB::table('oauth_client_secrets')->whereIn('oauth_client_id', array_values($ids))->count())->toBe(2);
    } finally {
        // MySQL commits DDL implicitly, so the suite's wrapping transaction may no longer
        // hold these rows back. Remove them explicitly; the secrets cascade.
        DB::table('oauth_client_secrets')->whereIn('oauth_client_id', array_values($ids))->delete();
        DB::table('oauth_clients')->whereIn('id', array_values($ids))->delete();
    }
});

it('rolls the table back off, leaving each client its newest secret in the old column', function (): void {
    $registered = $this->makeClient();
    $rotated = app(ClientRegistry::class)->rotateSecret($registered->client, 3600);

    $migration = require __DIR__.'/../../../database/migrations/2026_09_24_000200_create_oauth_client_secrets_table.php';

    $migration->down();

    try {
        expect(Schema::hasTable('oauth_client_secrets'))->toBeFalse()
            ->and(DB::table('oauth_clients')->where('id', $registered->client->id)->value('secret_hash'))
            ->toBe(hash('sha256', $rotated->secret));
        $migration->up();

        // And forward again, moving that newest secret back in.
        expect(app(ClientRegistry::class)->verifySecret($registered->client, $rotated->secret))->toBeTrue();
    } finally {
        if (! Schema::hasTable('oauth_client_secrets')) {
            $migration->up();
        }

        // See above: on MySQL the DDL committed this client.
        DB::table('oauth_clients')->where('id', $registered->client->id)->delete();
    }
});
