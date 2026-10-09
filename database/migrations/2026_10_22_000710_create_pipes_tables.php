<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // A pipe: one environment's OAuth app at one third-party provider. The client
        // secret is SEALED (SecretBox, bound to the row id) — the platform has to present
        // it to the provider, so it must be recoverable, never merely hashed. One pipe per
        // provider per environment: the lease API addresses a pipe by its provider.
        Schema::create('pipes', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('provider', 64);
            $table->string('client_id', 512);
            $table->text('client_secret_encrypted');
            $table->json('scopes');
            $table->json('parameters')->nullable();
            $table->boolean('enabled')->default(true);
            $table->timestamps();

            $table->unique(['environment_id', 'provider']);
        });

        // Which apps (OAuth client ids) may lease tokens through a pipe. No row ⇒ no lease.
        Schema::create('pipe_grants', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('pipe_id', 26)->index();
            $table->string('client_id', 191);
            $table->timestamps();

            $table->unique(['environment_id', 'pipe_id', 'client_id']);
        });

        // One person's connected account at one pipe's provider. The tokens are NOT here:
        // they are token-vault secrets owned by the user (sealed, audited, erased with the
        // person), and this row only names them. `refresh_claimed_until` is the
        // single-flight claim — an atomic UPDATE takes it, so two workers never spend the
        // same refresh token (a provider that rotates refresh tokens would revoke the grant
        // on the second use).
        Schema::create('pipe_connections', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('pipe_id', 26)->index();
            $table->string('provider', 64);
            $table->string('user_id', 128);
            $table->string('status', 32)->default('active');
            $table->string('access_secret_id', 26);
            $table->string('refresh_secret_id', 26)->nullable();
            $table->json('scopes')->nullable();
            $table->json('metadata')->nullable();
            $table->string('account_label', 255)->nullable();
            $table->timestamp('access_expires_at')->nullable();
            $table->timestamp('connected_at')->nullable();
            $table->timestamp('last_refreshed_at')->nullable();
            $table->timestamp('refresh_claimed_until')->nullable();
            $table->unsignedInteger('refresh_failures')->default(0);
            $table->string('last_error', 64)->nullable();
            $table->string('reauth_reason', 64)->nullable();
            $table->timestamps();

            $table->unique(['environment_id', 'pipe_id', 'user_id']);
            $table->index(['environment_id', 'user_id']);
            // The refresh sweep: active connections whose access token is about to expire.
            $table->index(['status', 'access_expires_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('pipe_connections');
        Schema::dropIfExists('pipe_grants');
        Schema::dropIfExists('pipes');
    }
};
