<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Previous password HASHES, retained only so a reuse policy can be enforced. Never a
 * readable credential, and only as deep as the policy actually compares against — the
 * enforcer prunes beyond that.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('password_history', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->ulid('user_id');
            $table->string('password_hash');
            $table->timestamps();

            // The lookup is "this subject's most recent N".
            $table->index(['user_id', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('password_history');
    }
};
