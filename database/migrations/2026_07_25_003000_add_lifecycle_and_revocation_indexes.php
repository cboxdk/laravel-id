<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The indexes the two things that walk these tables by something other than their
 * primary key actually need: revocation ("log out everywhere") and the new
 * `cbox-id:prune` sweep.
 *
 * Index coverage across the platform is broadly good — an env-first composite
 * convention, `unique()` on every token-hash column, and three deliberate
 * index-tuning migrations already landed. These are specific gaps, not a systemic
 * one, and each entry below names the query it serves.
 *
 * Every composite is environment-first, matching the existing convention: the hard
 * environment scope prepends `WHERE environment_id = ?` to every one of these
 * queries, so an index that does not lead with it cannot be used for the equality.
 *
 * Additive only — no column changes, no data movement, safe under a rolling deploy.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('oauth_refresh_tokens', function (Blueprint $table): void {
            // RefreshTokenService::revokeForUser() — `WHERE environment_id = ? AND
            // user_id = ? [AND organization_id = ?] AND revoked_at IS NULL`. This runs
            // on EVERY role change (the host's RevokeTokensOnRoleChange listener) and
            // on every password reset, against one of the largest tables in the system,
            // with neither `user_id` nor `organization_id` indexed at all.
            $table->index(['environment_id', 'user_id', 'organization_id'], 'oauth_refresh_tokens_env_user_org_index');

            // cbox-id:prune — `WHERE expires_at < ?`.
            $table->index('expires_at');
        });

        Schema::table('oauth_access_tokens', function (Blueprint $table): void {
            // The same admin revoke-all shape. `client_id` is indexed (the service
            // account retirement path uses it); the subject columns were not.
            $table->index(['environment_id', 'user_id', 'organization_id'], 'oauth_access_tokens_env_user_org_index');

            // cbox-id:prune — `WHERE expires_at < ?`.
            $table->index('expires_at');
        });

        Schema::table('oauth_authorization_codes', function (Blueprint $table): void {
            // cbox-id:prune — `WHERE expires_at < ?`.
            $table->index('expires_at');
        });

        Schema::table('auth_sessions', function (Blueprint $table): void {
            // DatabaseSessionManager::revokeAllForUser() and the per-user session list
            // in the console — `WHERE environment_id = ? AND user_id = ?`. Both columns
            // carried a SEPARATE single-column index, which is the wrong shape: the
            // optimizer picks one and filters the rest.
            $table->index(['environment_id', 'user_id'], 'auth_sessions_env_user_index');

            // cbox-id:prune — `WHERE expires_at < ?`. Also the natural index for
            // "sessions still alive", which had none.
            $table->index('expires_at');
        });

        Schema::table('webhook_deliveries', function (Blueprint $table): void {
            // HttpWebhookDispatcher::retryPending() filters status AND next_retry_at
            // together. Separate single-column indexes on each means the optimizer uses
            // one and filters the other — and `status` is extremely low-cardinality, so
            // it is usually the worse of the two to lead with. The sibling SIEM package
            // already solves this with a (stream_id, status, next_attempt_at) composite.
            $table->index(['environment_id', 'status', 'next_retry_at'], 'webhook_deliveries_env_status_retry_index');
        });

        Schema::table('provisioning_operations', function (Blueprint $table): void {
            // OutboxProvisioningService's drain — `WHERE environment_id = ? AND
            // connection_id = ? AND status IN (...) AND (next_attempt_at IS NULL OR
            // next_attempt_at <= ?)`. Same gap, same shape.
            $table->index(
                ['environment_id', 'connection_id', 'status', 'next_attempt_at'],
                'provisioning_operations_drain_index',
            );
        });
    }

    public function down(): void
    {
        Schema::table('oauth_refresh_tokens', function (Blueprint $table): void {
            $table->dropIndex('oauth_refresh_tokens_env_user_org_index');
            $table->dropIndex(['expires_at']);
        });

        Schema::table('oauth_access_tokens', function (Blueprint $table): void {
            $table->dropIndex('oauth_access_tokens_env_user_org_index');
            $table->dropIndex(['expires_at']);
        });

        Schema::table('oauth_authorization_codes', function (Blueprint $table): void {
            $table->dropIndex(['expires_at']);
        });

        Schema::table('auth_sessions', function (Blueprint $table): void {
            $table->dropIndex('auth_sessions_env_user_index');
            $table->dropIndex(['expires_at']);
        });

        Schema::table('webhook_deliveries', function (Blueprint $table): void {
            $table->dropIndex('webhook_deliveries_env_status_retry_index');
        });

        Schema::table('provisioning_operations', function (Blueprint $table): void {
            $table->dropIndex('provisioning_operations_drain_index');
        });
    }
};
