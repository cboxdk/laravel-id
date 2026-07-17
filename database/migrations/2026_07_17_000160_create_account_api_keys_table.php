<?php

declare(strict_types=1);

use Cbox\Id\Platform\Enums\AccountRole;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Account API keys — the machine credential for the ACCOUNT management plane (the
 * programmatic equivalent of an account member's console session). Global, above
 * environments: an account key can list/create environments, manage members, and
 * read billing, gated by the {@see AccountRole} it carries.
 *
 * Deliberately distinct from environment-scoped credentials (OAuth clients, M2M
 * tokens), which are locked to a single environment and can never reach account
 * operations — credentials never cross planes.
 *
 * Only the SHA-256 hash is stored; the plaintext (`cbid_acc_…`) is shown once at
 * creation. `prefix` is a non-secret display fragment so a key is recognisable in
 * a list without revealing it.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('account_api_keys', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->foreignUlid('account_id')->constrained('accounts')->cascadeOnDelete();
            $table->string('name');
            $table->string('prefix', 16);
            $table->string('token_hash', 64)->unique();
            $table->string('role');
            $table->timestamp('last_used_at')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();

            $table->index('account_id');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('account_api_keys');
    }
};
