<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Authentication policy per tenant: the environment baseline (null `organization_id`)
 * and each organization's override.
 *
 * Columns rather than a JSON blob so every rule is queryable, typed at the schema, and
 * cannot drift into an untyped bag as the set grows.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_policies', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();

            // Null = the environment baseline every organization inherits.
            $table->ulid('organization_id')->nullable();

            $table->unsignedSmallInteger('min_length')->default(12);
            $table->boolean('require_breach_check')->default(true);
            $table->unsignedSmallInteger('max_age_days')->nullable();
            $table->unsignedTinyInteger('reuse_history')->default(0);
            $table->string('mfa')->default('optional');
            $table->string('sso')->default('off');
            $table->unsignedSmallInteger('lockout_threshold')->nullable();

            $table->timestamps();

            // One baseline per environment, one override per organization. Note SQL
            // treats NULLs as distinct, so the baseline row's uniqueness is enforced by
            // the writer's updateOrCreate rather than by this index.
            $table->unique(['environment_id', 'organization_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_policies');
    }
};
