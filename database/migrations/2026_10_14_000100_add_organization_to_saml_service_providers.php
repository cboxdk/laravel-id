<?php

declare(strict_types=1);

use Cbox\Id\SamlIdp\SamlIdentityProviderService;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The organization a SAML service provider belongs to, or null for an environment-wide
 * one.
 *
 * Until this column existed every registered SP was environment-wide, and the IdP never
 * asked whether the subject it was asserting had anything to do with the SP's owner — so
 * any person in an environment could single-sign-on into any organization's SAML app.
 * An org-owned SP now only receives assertions for active members of its organization
 * ({@see SamlIdentityProviderService::issueResponse()}).
 *
 * Nullable, and every existing row stays null: an SP registered before this release
 * keeps exactly the behaviour it had. Additive and portable — a 26-character ULID column
 * (never `char`), indexed because the console lists an organization's apps by it.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('saml_service_providers', function (Blueprint $table): void {
            $table->string('organization_id', 26)->nullable()->after('environment_id');
            $table->index('organization_id', 'saml_service_providers_organization_id_index');
        });
    }

    public function down(): void
    {
        Schema::table('saml_service_providers', function (Blueprint $table): void {
            $table->dropIndex('saml_service_providers_organization_id_index');
            $table->dropColumn('organization_id');
        });
    }
};
