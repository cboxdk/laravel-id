<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * An organization that does NOT offer one of its environment's sign-in providers.
 *
 * A catalogue provider owned by the environment (`connections.organization_id` null) is
 * offered on every organization's sign-in page — that is what owning it at the environment
 * means. An organization that wants it gone from its own page without configuring its own
 * replacement records that here: one row per (organization, provider key).
 *
 * Keyed on the PROVIDER KEY, not on a connection id, deliberately: the environment's Google
 * can be removed and set up again with new credentials, and an organization that said "no
 * Google on our page" meant Google, not one particular row of it.
 *
 * Nothing destructive happens to existing data: an organization with no row here inherits
 * every environment provider, and environments had none before this release.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('sign_in_provider_opt_outs', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('organization_id', 26);
            $table->string('provider', 100);
            $table->timestamps();

            $table->unique(['environment_id', 'organization_id', 'provider'], 'sign_in_provider_opt_outs_unique');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('sign_in_provider_opt_outs');
    }
};
