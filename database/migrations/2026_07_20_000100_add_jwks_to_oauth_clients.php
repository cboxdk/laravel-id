<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * A confidential client's registered public JWK Set, for `private_key_jwt` client
 * authentication (RFC 7523 / OIDC Core §9): instead of a shared secret, the client
 * signs a short-lived assertion with its private key and the token endpoint verifies
 * it against this public set. Null = the client authenticates by secret (or `none`).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->json('jwks')->nullable()->after('secret_hash');
        });
    }

    public function down(): void
    {
        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->dropColumn('jwks');
        });
    }
};
