<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Relying service providers that federate to this platform as their IdP.
        // Environment-owned; `entity_id` is unique per environment. `acs_url` is
        // the single, exact URL an assertion may be POSTed to (open-redirect
        // defense). `certificate` is the SP's signing cert used to verify signed
        // AuthnRequests.
        Schema::create('saml_service_providers', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->string('entity_id');
            $table->text('acs_url');
            $table->string('name_id_format')->default('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
            $table->string('name_id_attribute')->default('email');
            $table->json('attribute_mappings');
            $table->text('certificate')->nullable();
            $table->boolean('want_authn_requests_signed')->default(false);
            $table->string('status')->default('active');
            $table->timestamps();

            // EntityID is unique within an environment, never globally — two tenants
            // may legitimately register the same SP EntityID in separate planes.
            $table->unique(['environment_id', 'entity_id']);
        });

        // The self-signed X.509 cert wrapping the platform signing key, keyed by
        // kid, so metadata publishes a stable cert per signing key and rotation is
        // reflected automatically. Public material; the private key stays sealed.
        Schema::create('saml_idp_certificates', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->string('kid');
            $table->text('certificate');
            $table->timestamps();

            $table->unique(['environment_id', 'kid']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('saml_idp_certificates');
        Schema::dropIfExists('saml_service_providers');
    }
};
