<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Single-use, short-lived password-reset tokens. Only the SHA-256 hash is
        // stored; the raw token is emailed once.
        //
        // Deliberately NOT `password_reset_tokens` — that name belongs to Laravel's
        // own `create_users_table` skeleton migration, which is present in EVERY
        // freshly scaffolded app and creates a differently shaped table of that
        // name. Sharing it made `composer require cboxdk/laravel-id && php artisan
        // migrate` fail with "table already exists" on a greenfield install, on
        // every engine. Same reasoning as `user_api_tokens` vs Sanctum's
        // `personal_access_tokens`.
        Schema::create('cbox_id_password_reset_tokens', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('email')->index();
            $table->string('token_hash')->unique();
            $table->timestamp('expires_at');
            $table->timestamp('consumed_at')->nullable();
            $table->timestamps();
        });

        // Email-verification tokens, bound to the subject whose address is being
        // confirmed. Hash-only, single-use.
        Schema::create('email_verification_tokens', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('user_id')->index();
            $table->string('email');
            $table->string('token_hash')->unique();
            $table->timestamp('expires_at');
            $table->timestamp('consumed_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('email_verification_tokens');
        Schema::dropIfExists('cbox_id_password_reset_tokens');
    }
};
