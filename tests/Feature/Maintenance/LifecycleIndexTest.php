<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

/**
 * The indexed columns of a table, as a list of column-name lists — read from the
 * database itself rather than asserted against the migration, so a migration that
 * silently failed to apply is caught.
 *
 * @return list<list<string>>
 */
function indexedColumns(string $table): array
{
    $connection = Schema::getConnection();

    // The suite runs on SQLite; this reads the same catalogue the planner does.
    if ($connection->getDriverName() !== 'sqlite') {
        return array_map(
            static fn (array $index): array => array_values($index['columns']),
            Schema::getIndexes($table),
        );
    }

    $indexes = [];

    foreach (DB::select('PRAGMA index_list('.$table.')') as $index) {
        $columns = [];

        foreach (DB::select('PRAGMA index_info('.$index->name.')') as $column) {
            $columns[] = $column->name;
        }

        $indexes[] = $columns;
    }

    return $indexes;
}

it('indexes the revocation and sweep paths that were full scans', function (string $table, array $columns): void {
    expect(indexedColumns($table))->toContain($columns);
})->with([
    // RefreshTokenService::revokeForUser() — runs on every role change.
    'refresh tokens by user' => ['oauth_refresh_tokens', ['environment_id', 'user_id', 'organization_id']],
    'refresh token expiry' => ['oauth_refresh_tokens', ['expires_at']],
    'access tokens by user' => ['oauth_access_tokens', ['environment_id', 'user_id', 'organization_id']],
    'access token expiry' => ['oauth_access_tokens', ['expires_at']],
    'authorization code expiry' => ['oauth_authorization_codes', ['expires_at']],
    // DatabaseSessionManager::revokeAllForUser() — "log out everywhere".
    'sessions by user' => ['auth_sessions', ['environment_id', 'user_id']],
    'session expiry' => ['auth_sessions', ['expires_at']],
    // HttpWebhookDispatcher::retryPending() filters status AND next_retry_at together.
    'webhook retry sweep' => ['webhook_deliveries', ['environment_id', 'status', 'next_retry_at']],
    'provisioning drain' => ['provisioning_operations', ['environment_id', 'connection_id', 'status', 'next_attempt_at']],
    // The fastest-growing table in the system had no expiry index at all, while the
    // identically-purposed consumed_assertions has had one since day one.
    'dpop proof expiry' => ['dpop_proofs', ['expires_at']],
]);

it('keys dpop proofs by thumbprint AND nonce, not the client-chosen nonce alone', function (): void {
    expect(indexedColumns('dpop_proofs'))
        ->toContain(['jkt', 'jti'])
        ->not->toContain(['jti']);
});
