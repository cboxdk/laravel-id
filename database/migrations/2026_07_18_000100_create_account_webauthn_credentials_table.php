<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Passkeys (WebAuthn credentials) for account members — the buyer plane's
 * strongest factor. A SEPARATE store from subject passkeys (webauthn_credentials),
 * keyed by account_member_id and NOT environment-owned: account members live above
 * every environment. The cryptographic verification is shared with the subject
 * plane via the vetted WebAuthnVerifier; only the storage plane differs.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('account_webauthn_credentials', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->foreignUlid('account_member_id')->constrained('account_members')->cascadeOnDelete();
            $table->string('credential_id')->unique();
            $table->text('public_key');
            $table->unsignedBigInteger('sign_count')->default(0);
            $table->json('transports')->default('[]');
            $table->string('name')->nullable();
            $table->timestamps();

            $table->index('account_member_id');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('account_webauthn_credentials');
    }
};
