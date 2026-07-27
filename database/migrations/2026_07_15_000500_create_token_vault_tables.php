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
            // EXPLICIT LENGTHS: `name`, `owner_type` and `owner_id` are all covered by
            // the unique index below, and at the framework's varchar(255) default that
            // key is 26*4 + 3*255*4 = 3164 bytes — 92 over InnoDB's 3072-byte cap, so
            // MySQL refused it (error 1071). 104 + 512 + 512 + 512 = 1640 bytes now.
            // A secret name is an operator-chosen key ('smtp', 'github-token') and the
            // owner is a morph type plus a ULID, so 128 is far above the real ceiling.
            $table->string('name', 128);
            $table->string('provider');
            $table->text('secret_encrypted');
            $table->unsignedInteger('key_version')->default(1);
            $table->string('owner_type', 128)->nullable();
            $table->string('owner_id', 128)->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamp('rotated_at')->nullable();
            $table->timestamps();

            // A secret name is unique within an OWNER, not merely within an environment.
            // An environment holds many organizations, so an env-wide unique name let one
            // tenant squat a name every other tenant legitimately wants ("smtp",
            // "github-token") — and the constraint violation told them the name was taken,
            // an existence oracle across the tenant boundary. Env-first so the hard scope's
            // WHERE environment_id lookups still hit the index.
            //
            // Deliberate caveat: SQL treats NULLs as distinct in a unique index, so this
            // does not constrain unowned (platform) secrets against each other. That set is
            // operator-managed and small; every tenant-facing path carries an owner.
            $table->unique(['environment_id', 'owner_type', 'owner_id', 'name']);
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
