<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The sign-in session a grant was issued from.
 *
 * An ID Token carries `sid` so a relying party can match a later logout token to the
 * local session it created (Back-Channel Logout 1.0 §2.1). The session is known at
 * /authorize and gone by the token endpoint, so the code carries it across; the refresh
 * family carries it on, so a refreshed ID Token names the same session as the first.
 *
 * Nullable, and never backfilled: a code or family issued before this migration has no
 * recorded session, and inventing one would put a `sid` on a token that no logout can
 * ever match. Such grants simply carry no `sid`.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('oauth_authorization_codes', function (Blueprint $table): void {
            $table->string('session_id', 64)->nullable();
        });

        Schema::table('oauth_refresh_tokens', function (Blueprint $table): void {
            $table->string('session_id', 64)->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('oauth_authorization_codes', function (Blueprint $table): void {
            $table->dropColumn('session_id');
        });

        Schema::table('oauth_refresh_tokens', function (Blueprint $table): void {
            $table->dropColumn('session_id');
        });
    }
};
