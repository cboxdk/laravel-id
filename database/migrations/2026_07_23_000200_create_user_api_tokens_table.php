<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Deliberately NOT `personal_access_tokens` — that name belongs to
        // Sanctum's default table and a host app may run both.
        Schema::create('user_api_tokens', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->ulid('organization_id')->index();
            $table->ulid('user_id');
            $table->string('name');
            $table->string('prefix', 16);
            $table->string('token_hash', 64)->unique();
            $table->string('scope');
            $table->json('resource_families')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();

            $table->index(['organization_id', 'user_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('user_api_tokens');
    }
};
