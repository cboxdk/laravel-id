<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * What the ORIGINAL login established, carried by the rotation family.
 *
 * A refresh response may include an ID Token, and when it does OIDC Core §12.2
 * is explicit that `auth_time` must still describe the moment the user actually
 * authenticated — not the moment the token was refreshed. The same holds for
 * the methods they used: a relying party that gates a step-up on `amr`/`acr`
 * would otherwise watch a session silently downgrade at its first refresh,
 * which looks like the user losing their second factor.
 *
 * Nullable, so every refresh token issued before this migration keeps working
 * and simply carries no authentication context — the claims are optional, and
 * a missing one is honest where a fabricated one would not be.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('oauth_refresh_tokens', function (Blueprint $table): void {
            $table->unsignedInteger('auth_time')->nullable()->after('audience');
            $table->json('amr')->nullable()->after('auth_time');
        });
    }

    public function down(): void
    {
        Schema::table('oauth_refresh_tokens', function (Blueprint $table): void {
            $table->dropColumn(['auth_time', 'amr']);
        });
    }
};
