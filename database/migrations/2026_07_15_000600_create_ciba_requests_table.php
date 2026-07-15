<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // OpenID Connect CIBA request: the auth_req_id is stored as a SHA-256 hash
        // (the raw value is the client's polling secret). The user is resolved from
        // the request's login_hint up front and bound as user_id.
        Schema::create('ciba_requests', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->string('auth_req_id_hash')->unique();
            $table->string('client_id')->index();
            $table->string('user_id');
            $table->string('organization_id')->nullable();
            $table->json('scopes')->default('[]');
            $table->string('binding_message')->nullable();
            $table->string('nonce')->nullable();
            $table->string('status')->default('pending'); // pending | approved | denied | redeemed
            $table->unsignedInteger('interval')->default(5);
            $table->timestamp('last_polled_at')->nullable();
            $table->timestamp('approved_at')->nullable();
            $table->timestamp('expires_at');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('ciba_requests');
    }
};
