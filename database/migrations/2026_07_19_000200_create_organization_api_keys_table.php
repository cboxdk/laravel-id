<?php

declare(strict_types=1);

use Cbox\Id\Platform\Enums\AccountRole;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Organization API keys — the machine credential for the MANAGEMENT plane, the
 * programmatic equivalent of a member's console session. Global, above environments: a
 * key can list and create environments, manage members and read billing, gated by the
 * {@see MembershipRole} it carries.
 *
 * ONE ROLE VOCABULARY, and that is the whole reason this table moved. It was keyed on
 * `accounts` and carried an `AccountRole`, while the console asked a `MembershipRole` —
 * two enums answering the same question about the same customer, and they disagreed: a
 * `billing` key could manage billing and not read the member roster, while a human
 * holding the same role in the console got exactly the opposite. A machine credential
 * that answers differently from the session it stands in for is not a second opinion,
 * it is a second authorization system.
 *
 * Deliberately distinct from environment-scoped credentials (OAuth clients, M2M
 * tokens), which are locked to a single environment and can never reach management
 * operations — credentials never cross planes.
 *
 * Only the SHA-256 hash is stored; the plaintext (`cbid_org_…`) is shown once at
 * creation. `prefix` is a non-secret display fragment so a key is recognisable in
 * a list without revealing it.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('organization_api_keys', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            // The ORGANIZATION the key acts for. No foreign key: `organizations` is
            // environment-owned and the platform plane does not take referential locks
            // across the tenancy boundary.
            $table->string('organization_id', 26)->index();
            $table->string('name');
            $table->string('prefix', 16);
            $table->string('token_hash', 64)->unique();
            $table->string('role');
            $table->timestamp('last_used_at')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();

        });
    }

    public function down(): void
    {
        Schema::dropIfExists('organization_api_keys');
    }
};
