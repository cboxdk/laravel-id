<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Environment API keys — the machine credential for the ENVIRONMENT management plane
 * (orgs, users, roles, directories within one environment). Environment-OWNED
 * (unlike account keys, which are global): a key belongs to exactly one environment
 * and can only ever act inside it, so it can never reach the account plane or
 * another environment. Served on the environment's own host; the request's resolved
 * environment must match the key's.
 *
 * Only the SHA-256 hash is stored; the plaintext (`cbid_env_…`) is shown once.
 * `scopes` bound what the key can do (deny-by-default), finer-grained than a role.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('environment_api_keys', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->string('name');
            $table->string('prefix', 16);
            $table->string('token_hash', 64)->unique();
            $table->json('scopes')->default('[]');
            $table->timestamp('last_used_at')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('environment_api_keys');
    }
};
