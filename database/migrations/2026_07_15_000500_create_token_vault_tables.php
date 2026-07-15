<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Downstream third-party credentials, sealed at rest (SecretBox). The
        // `secret_encrypted` column holds the base64url AEAD ciphertext, never a
        // plaintext or a hash — the vault must be able to replay the value.
        Schema::create('vault_secrets', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->string('name');
            $table->string('provider');
            $table->text('secret_encrypted');
            $table->unsignedInteger('key_version')->default(1);
            $table->string('owner_type')->nullable();
            $table->string('owner_id')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamp('rotated_at')->nullable();
            $table->timestamps();

            // A secret name is unique within an environment; env-first so the hard
            // scope's WHERE environment_id lookups hit the index.
            $table->unique(['environment_id', 'name']);
            $table->index(['environment_id', 'owner_type', 'owner_id']);
        });

        // The deny-by-default authorization edge: which agent client may lease
        // which secret. No live row for a (secret, client) pair means refused.
        Schema::create('vault_grants', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->ulid('secret_id')->index();
            $table->string('client_id');
            $table->unsignedInteger('max_ttl_seconds')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();

            $table->unique(['environment_id', 'secret_id', 'client_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('vault_grants');
        Schema::dropIfExists('vault_secrets');
    }
};
