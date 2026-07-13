<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oauth_refresh_tokens', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->string('token_hash')->unique();
            // A rotation lineage: every refresh derived from the same original
            // login shares a family_id, so detecting reuse of a rotated token lets
            // us revoke the whole family at once.
            $table->string('family_id')->index();
            $table->string('client_id')->index();
            $table->ulid('user_id')->nullable();
            $table->ulid('organization_id')->nullable();
            $table->json('scopes')->default('[]');
            $table->string('audience')->nullable();
            // RFC 9449 §5: when the token was issued under DPoP, the client's key
            // thumbprint is bound here so rotation must present the same key — a
            // stolen public-client refresh token can't be redeemed with another key.
            $table->string('jkt')->nullable();
            $table->timestamp('consumed_at')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamp('expires_at');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oauth_refresh_tokens');
    }
};
