<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Feature flags: a named switch per environment, with its default and its
        // kill switch. `rollout_percentage` (0–100, null for none) lives on the flag
        // because there is exactly one per flag; per-user and per-organization rules
        // are rows of their own below.
        Schema::create('feature_flags', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26);
            // What code asks for and what the `feature_flags` claim carries. Fixed once
            // created; 64 is far above any real key ('new-dashboard', 'billing.v2').
            $table->string('key', 64);
            $table->string('description', 500)->nullable();
            $table->boolean('enabled')->default(true);
            $table->boolean('default_value')->default(false);
            $table->unsignedTinyInteger('rollout_percentage')->nullable();
            $table->timestamps();

            // Env-first, so the hard scope's WHERE environment_id lookups use it too.
            $table->unique(['environment_id', 'key'], 'feature_flags_env_key_unique');
        });

        // Targeting rules: on (or off) for one user or one organization. `target_id` is
        // the host's user id or an organization ULID; 128 covers any user key a host
        // brings (a UUID, an integer, an external subject).
        Schema::create('feature_flag_targets', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26);
            $table->string('feature_flag_id', 26);
            $table->string('target_type', 16);
            $table->string('target_id', 128);
            $table->boolean('enabled')->default(true);
            $table->timestamps();

            $table->unique(['feature_flag_id', 'target_type', 'target_id'], 'feature_flag_targets_rule_unique');
            // Erasure and "which flags name this organization?" look a target up across
            // every flag in the environment.
            $table->index(['environment_id', 'target_type', 'target_id'], 'feature_flag_targets_subject_index');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('feature_flag_targets');
        Schema::dropIfExists('feature_flags');
    }
};
