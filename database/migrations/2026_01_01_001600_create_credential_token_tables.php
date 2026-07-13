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
        Schema::create('password_reset_tokens', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->string('email')->index();
            $table->string('token_hash')->unique();
            $table->timestamp('expires_at');
            $table->timestamp('consumed_at')->nullable();
            $table->timestamps();
        });

        // Email-verification tokens, bound to the subject whose address is being
        // confirmed. Hash-only, single-use.
        Schema::create('email_verification_tokens', function (Blueprint $table): void {
            $table->ulid('id')->primary();
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
        Schema::dropIfExists('password_reset_tokens');
    }
};
