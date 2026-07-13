<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('mfa_factors', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->ulid('user_id')->index();
            $table->string('type');
            $table->text('secret_encrypted');
            $table->timestamp('confirmed_at')->nullable();
            // The most recent TOTP time step accepted for this factor. A code at
            // this step or earlier is rejected as a replay.
            $table->unsignedBigInteger('last_used_step')->nullable();
            $table->timestamps();

            $table->unique(['user_id', 'type']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('mfa_factors');
    }
};
