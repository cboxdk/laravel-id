<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

/**
 * More than one live secret per OAuth client.
 *
 * A client had exactly one `secret_hash`, so "rotate" meant "replace": the new secret
 * worked and the old one stopped in the same write, and every deployment still holding the
 * old one failed at its next token request. There was no way to hand out the new secret
 * first and retire the old one once it had been rolled out. This table is that window: a
 * rotation adds a row and gives the previous rows an `expires_at`.
 *
 * THE BACKFILL MOVES EVERY EXISTING SECRET, with no expiry, so a client that authenticated
 * before the upgrade authenticates after it with the same secret. Nothing is re-derived —
 * only the SHA-256 is stored and only the SHA-256 is compared. There is no `hint` for
 * these rows: the hint is taken from the plaintext, and the plaintext was never kept.
 *
 * `oauth_clients.secret_hash` STAYS for 1.19 as a read-only mirror of the newest live
 * secret, so code that reads it keeps working for one minor. It is never consulted to
 * authenticate. See UPGRADING.md.
 *
 * Written as raw queries, no models: models carry global scopes (clients are
 * environment-owned) and drift with the codebase, and a migration has to keep meaning what
 * it meant on the day it ran.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasTable('oauth_client_secrets')) {
            Schema::create('oauth_client_secrets', function (Blueprint $table): void {
                $table->string('id', 26)->primary();
                $table->string('environment_id', 26)->index();
                // The client's primary key, not its public `client_id`: the row belongs to
                // one client record, and a key that cascades is the one that cannot outlive it.
                $table->string('oauth_client_id', 26);
                $table->string('secret_hash', 64);
                // The last few characters of the plaintext, so an operator can tell which
                // of two live secrets a deployment holds. Null for backfilled secrets.
                $table->string('hint', 8)->nullable();
                $table->timestamp('expires_at')->nullable();
                $table->timestamp('last_used_at')->nullable();
                $table->timestamps();

                $table->index(['oauth_client_id', 'expires_at']);
                $table->foreign('oauth_client_id')->references('id')->on('oauth_clients')->cascadeOnDelete();
            });
        }

        $now = now();

        DB::table('oauth_clients')
            ->whereNotNull('secret_hash')
            ->where('secret_hash', '!=', '')
            ->orderBy('id')
            ->select(['id', 'environment_id', 'secret_hash', 'created_at', 'updated_at'])
            ->chunk(500, function ($clients) use ($now): void {
                $rows = [];

                foreach ($clients as $client) {
                    $clientId = is_string($client->id) ? $client->id : '';
                    $hash = is_string($client->secret_hash) ? $client->secret_hash : '';

                    if ($clientId === '' || $hash === '') {
                        continue;
                    }

                    // Idempotent: a re-run after a partial one moves nothing twice.
                    $already = DB::table('oauth_client_secrets')
                        ->where('oauth_client_id', $clientId)
                        ->where('secret_hash', $hash)
                        ->exists();

                    if ($already) {
                        continue;
                    }

                    $rows[] = [
                        'id' => Str::lower((string) Str::ulid()),
                        'environment_id' => $client->environment_id,
                        'oauth_client_id' => $clientId,
                        'secret_hash' => $hash,
                        'hint' => null,
                        'expires_at' => null,
                        'last_used_at' => null,
                        // When the secret was set is not recorded anywhere; the client's
                        // last write is the closest honest answer.
                        'created_at' => $client->updated_at ?? $client->created_at ?? $now,
                        'updated_at' => $now,
                    ];
                }

                if ($rows !== []) {
                    DB::table('oauth_client_secrets')->insert($rows);
                }
            });
    }

    public function down(): void
    {
        // `oauth_clients.secret_hash` was kept in step with the newest live secret the
        // whole time, so dropping the table leaves every client with the credential it
        // would have had under the single-secret model.
        Schema::dropIfExists('oauth_client_secrets');
    }
};
