<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Database\JsonDefault;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Support sessions: an app vendor's staff (or an environment administrator) acting AS one
 * customer's user in one app, for a stated reason and a bounded time (RFC 8693 `act`).
 *
 * The session row is the authority. Every authorization code minted for it carries its
 * id, the token endpoint re-reads it at redemption, and every access token minted from it
 * is tagged with it — so ending the session revokes what it issued, and a code or token
 * from an ended session is dead however it is presented.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('support_sessions', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            // The person acting, and in which capacity (staff | environment_admin).
            $table->string('actor_id');
            $table->string('actor_kind');
            // Whom they act as, where, and in which app.
            $table->string('target_user_id');
            $table->string('organization_id', 26);
            $table->string('client_id');
            // The scopes every code this session mints carries. Never offline_access.
            $table->json('scopes')->default(JsonDefault::emptyArray());
            // Required, and shown to the customer: the reason is the consent substitute.
            $table->text('reason');
            $table->timestamp('expires_at');
            $table->timestamp('ended_at')->nullable();
            $table->string('ended_by')->nullable();
            $table->timestamps();

            $table->index(['environment_id', 'actor_id'], 'support_sessions_actor_idx');
            $table->index(['environment_id', 'target_user_id'], 'support_sessions_target_idx');
        });

        // The acting party travels with the code into the token endpoint. Both null for
        // every ordinary code, so nothing about an existing grant changes.
        Schema::table('oauth_authorization_codes', function (Blueprint $table): void {
            $table->string('actor_id')->nullable();
            $table->string('support_session_id', 26)->nullable();
        });

        // Which session minted a token, so ending the session can revoke it.
        Schema::table('oauth_access_tokens', function (Blueprint $table): void {
            $table->string('support_session_id', 26)->nullable()->index();
        });
    }

    public function down(): void
    {
        Schema::table('oauth_access_tokens', function (Blueprint $table): void {
            $table->dropIndex(['support_session_id']);
            $table->dropColumn('support_session_id');
        });

        Schema::table('oauth_authorization_codes', function (Blueprint $table): void {
            $table->dropColumn(['actor_id', 'support_session_id']);
        });

        Schema::dropIfExists('support_sessions');
    }
};
