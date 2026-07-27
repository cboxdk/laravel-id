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

        // BOTH names, because a rollback reaches this migration by two routes. On a
        // database that came up through v0.62.0, `2026_07_27_000100`'s down() runs
        // first and renames the table BACK to `password_reset_tokens` — so dropping
        // only the new name left the table standing, and a full reset finished with
        // one surviving table and a name that then collides with Laravel's skeleton
        // migration on the way back up.
        //
        // Guarded by shape, never by name alone: Laravel's own skeleton table shares
        // the name and has neither column. This migration must not drop a table it
        // did not create.
        if (Schema::hasTable('password_reset_tokens')
            && Schema::hasColumn('password_reset_tokens', 'environment_id')
            && Schema::hasColumn('password_reset_tokens', 'token_hash')) {
            Schema::drop('password_reset_tokens');
        }
    }
};
