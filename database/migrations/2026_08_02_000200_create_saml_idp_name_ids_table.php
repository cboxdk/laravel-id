<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The opaque, per-service-provider identifier a Persistent NameID is supposed to be.
 *
 * `resolveNameId()` never consulted the format: it returned whatever the SP's
 * `name_id_attribute` pointed at, which defaults to `email`. So a NameID declared
 * `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` was the person's email address,
 * identical at every service provider — which is exactly the correlation SAML Core
 * §8.3.7 defines the format to prevent. Two SPs comparing notes could match their users
 * with no cooperation from us, and the identifier they compared was PII rather than a
 * pseudonym.
 *
 * Stored rather than derived. An HMAC over (SP, subject) with the IdP key would produce
 * the same value with no table — but it also fixes that value forever: a service
 * provider that leaks its user list cannot be re-keyed without changing every OTHER
 * provider's identifiers too, because they all descend from the same secret. A row can
 * be deleted and reissued for one SP alone.
 *
 * Transient (§8.3.8) needs no table: it MUST NOT be reused, so it is minted per
 * assertion and recorded on the `saml_idp_sessions` row, which is what Single Logout
 * resolves through.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('saml_idp_name_ids', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();

            // The EntityID rather than the registration's row id: an SP re-registered
            // after a deletion is a new row but the same protocol identity, and the
            // person's pseudonym at that provider should survive the re-registration.
            $table->string('sp_entity_id', 512);
            $table->string('subject_id', 26);

            // Opaque by construction — 128 bits of randomness, never derived from
            // anything about the subject.
            $table->string('name_id', 64);

            $table->timestamps();

            // 105 + 2050 + 105 = 2260 bytes in utf8mb4, inside InnoDB's 3072 limit.
            // Checked rather than assumed: the last table added here was 4200 and could
            // not be created on MySQL at all.
            $table->unique(['environment_id', 'sp_entity_id', 'subject_id'], 'saml_idp_name_ids_pairwise');

            // Single Logout resolves a NameID back to a subject through the SP that
            // presented it, so the reverse lookup needs to be indexed too.
            $table->index(['environment_id', 'name_id'], 'saml_idp_name_ids_lookup');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('saml_idp_name_ids');
    }
};
