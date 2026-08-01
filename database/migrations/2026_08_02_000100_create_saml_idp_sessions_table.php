<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Which subject we told which service provider about, and under what name.
 *
 * Single Logout had no way to answer that question, so it did the only thing it could:
 * take the NameID out of a signed `LogoutRequest`, look it up as a subject id OR an
 * email, and revoke every session that subject has anywhere.
 *
 * A NameID is not a secret. For the default `emailAddress` format it IS the person's
 * email address. So any service provider registered in the environment could sign a
 * LogoutRequest naming any user — one it had never seen, one that had never federated to
 * it — and terminate that person's identity-provider session and every downstream
 * session with it. Repeatedly. A relying party held a logout primitive over the whole
 * environment.
 *
 * With this record, SLO resolves the NameID THROUGH the requesting SP: only a subject we
 * actually issued an assertion to, for that SP, under that name, can be logged out by it.
 *
 * `session_index` is the value already minted into every assertion's `AuthnStatement`
 * (SAML Core §2.7.2) and previously thrown away. Recording it is what lets a conformant
 * SP log out ONE session rather than all of them, which is the difference between
 * closing a tab and ending someone's day.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('saml_idp_sessions', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();

            // The SP's EntityID rather than its row id: an SP re-registered after a
            // deletion is a different row but the same protocol identity, and the
            // LogoutRequest carries the EntityID.
            $table->string('sp_entity_id', 512);
            $table->string('subject_id', 26);

            // As SENT. A persistent NameID is opaque and SP-specific by construction, so
            // this is the only place the mapping back to a subject exists.
            $table->string('name_id', 512);
            $table->string('session_index', 64);

            $table->timestamp('expires_at')->nullable()->index();
            $table->timestamps();

            // The SLO lookup, in one index: "for this SP, who is this NameID?"
            $table->index(['environment_id', 'sp_entity_id', 'name_id'], 'saml_idp_sessions_lookup');
            $table->index(['environment_id', 'subject_id'], 'saml_idp_sessions_subject');
            $table->unique(['environment_id', 'session_index'], 'saml_idp_sessions_index');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('saml_idp_sessions');
    }
};
