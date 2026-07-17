<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Account-member MFA — a SEPARATE subsystem from operator and subject MFA, keyed
 * by account_member_id (the buyer plane, above every environment). The account
 * plane owns customers' IdPs, so its second factors matter most; keeping the three
 * planes' factors apart means one plane's factor is never mistaken for another's.
 *
 * TOTP secrets are stored sealed (Crypto SecretBox); recovery codes only as hashes.
 * Passkeys live in account_webauthn_credentials (separate migration).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('account_mfa_factors', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->foreignUlid('account_member_id')->constrained('account_members')->cascadeOnDelete();
            $table->string('type');
            $table->text('secret_encrypted');
            $table->timestamp('confirmed_at')->nullable();
            // Highest TOTP step already accepted — a code at or below it is a replay.
            $table->unsignedBigInteger('last_used_step')->nullable();
            $table->timestamps();

            $table->unique(['account_member_id', 'type']);
        });

        Schema::create('account_mfa_recovery_codes', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->foreignUlid('account_member_id')->constrained('account_members')->cascadeOnDelete();
            $table->string('code_hash');
            $table->timestamp('used_at')->nullable();
            $table->timestamps();

            $table->index('account_member_id');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('account_mfa_recovery_codes');
        Schema::dropIfExists('account_mfa_factors');
    }
};
