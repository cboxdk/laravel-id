<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Where a relying party wants to be told that a person signed out (OpenID Connect
 * Back-Channel Logout 1.0 §2.2).
 *
 * `backchannel_logout_uri` is the RP's endpoint; when it is null the client is never
 * notified, which is every client that existed before this migration — so nothing
 * changes for an app until it opts in. `backchannel_logout_session_required` records
 * that the RP needs `sid` in every logout token it receives; false is the spec default.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->string('backchannel_logout_uri', 2048)->nullable();
            $table->boolean('backchannel_logout_session_required')->default(false);
        });
    }

    public function down(): void
    {
        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->dropColumn(['backchannel_logout_uri', 'backchannel_logout_session_required']);
        });
    }
};
