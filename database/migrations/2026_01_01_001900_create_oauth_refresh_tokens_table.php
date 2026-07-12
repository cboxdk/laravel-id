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
