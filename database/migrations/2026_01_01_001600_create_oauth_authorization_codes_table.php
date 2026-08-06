<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Database\JsonDefault;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oauth_authorization_codes', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('code_hash')->unique();
            $table->string('client_id')->index();
            $table->string('user_id', 26);
            $table->string('organization_id', 26)->nullable();
            $table->string('redirect_uri');
            $table->json('scopes')->default(JsonDefault::emptyArray());
            $table->string('pkce_challenge');
            $table->string('pkce_method')->default('S256');
            // OIDC nonce from the authorize request, echoed into the id_token.
            $table->string('nonce')->nullable();
            // Authentication context captured at login, surfaced as id_token
            // auth_time / amr claims for the client's step-up decisions.
            $table->unsignedInteger('auth_time')->nullable();
            $table->json('amr')->nullable();
            $table->timestamp('expires_at');
            $table->timestamp('consumed_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oauth_authorization_codes');
    }
};
