<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Operator MFA is a SEPARATE subsystem from subject (user) MFA: operators
        // live above every environment, so these tables are NOT environment-owned
        // and are keyed by operator_id. Keeping the two identity planes' factors
        // apart is the point — an operator's second factor is never a tenant user's.
        Schema::create('operator_mfa_factors', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('operator_id')->index();
            $table->string('type');
            $table->text('secret_encrypted');
            $table->timestamp('confirmed_at')->nullable();
            // The most recent TOTP time step accepted; a code at this step or
            // earlier is rejected as a replay.
            $table->unsignedBigInteger('last_used_step')->nullable();
            $table->timestamps();

            $table->unique(['operator_id', 'type']);
        });

        Schema::create('operator_mfa_recovery_codes', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('operator_id')->index();
            // Only the hash is stored; the plaintext is shown once at generation.
            $table->string('code_hash');
            $table->timestamp('used_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('operator_mfa_recovery_codes');
        Schema::dropIfExists('operator_mfa_factors');
    }
};
