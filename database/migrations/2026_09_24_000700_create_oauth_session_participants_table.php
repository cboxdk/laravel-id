<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Which relying parties a sign-in session has signed a person in to.
 *
 * Back-Channel Logout needs the answer to "whom do I tell?" at the moment a session
 * ends, and nothing else records it: the authorization code is spent seconds after it
 * is issued, and a client without `offline_access` holds no refresh token at all. One
 * row per (session, client), written when a code minted from that session is redeemed.
 *
 * `ended_at` rather than a delete, so a logout that fans out twice (at-least-once event
 * delivery, a double click on "sign out everywhere") notifies each RP once.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oauth_session_participants', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26);
            // The session id as the host's SessionManager minted it — a ULID for the
            // bundled one, wider for a host that brings its own.
            $table->string('session_id', 64);
            $table->string('user_id', 26);
            $table->string('client_id');
            $table->string('organization_id', 26)->nullable();
            $table->timestamp('ended_at')->nullable();
            $table->timestamps();

            // One row per pair; the recorder upserts against this.
            $table->unique(['session_id', 'client_id'], 'oauth_sp_session_client_unique');
            // "Sign this person out everywhere" and "withdraw their access in this org".
            $table->index(['environment_id', 'user_id', 'ended_at'], 'oauth_sp_user_index');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oauth_session_participants');
    }
};
