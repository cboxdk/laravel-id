<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Each environment's SMS second-factor policy (`SmsFactorPolicy`): whether SMS is accepted,
 * which countries' numbers, and whether it may be an administrator's only factor.
 *
 * One row per environment at most. An environment with no row has the default — SMS OFF —
 * so creating this table changes nothing for anyone. The countries are a JSON list in a
 * text column, which reads the same on every supported engine.
 *
 * The phone numbers themselves are NOT here: an SMS factor is a row in `mfa_factors` of
 * type `sms`, its number sealed in the existing `secret_encrypted` column, so it is
 * rotated by `cbox-id:crypto:rewrap` and erased with the rest of a person's factors
 * without either needing to learn about a new table.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('sms_factor_policies', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->unique();
            $table->boolean('enabled')->default(false);
            $table->text('allowed_countries')->nullable();
            $table->boolean('privileged_need_stronger_factor')->default(true);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('sms_factor_policies');
    }
};
