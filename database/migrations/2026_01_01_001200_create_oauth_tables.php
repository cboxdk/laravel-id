<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oauth_clients', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('organization_id')->nullable()->index();
            $table->string('client_id')->unique();
            $table->string('secret_hash')->nullable();
            $table->string('name');
            $table->string('type')->default('confidential');
            $table->json('redirect_uris')->default('[]');
            $table->json('grant_types')->default('[]');
            $table->json('scopes')->default('[]');
            $table->boolean('first_party')->default(false);
            // RFC 7592: SHA-256 of the registration access token for dynamically
            // registered clients (null for clients created through the console).
            $table->string('registration_access_token_hash')->nullable();
            $table->timestamps();
        });

        Schema::create('oauth_service_accounts', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('organization_id')->index();
            $table->string('name');
            $table->string('client_id')->index();
            $table->string('status')->default('active');
            $table->timestamps();
        });

        Schema::create('oauth_access_tokens', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->string('jti')->unique();
            $table->string('client_id')->index();
            $table->ulid('user_id')->nullable();
            $table->ulid('organization_id')->nullable();
            $table->json('scopes')->default('[]');
            $table->timestamp('expires_at');
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oauth_access_tokens');
        Schema::dropIfExists('oauth_service_accounts');
        Schema::dropIfExists('oauth_clients');
    }
};
