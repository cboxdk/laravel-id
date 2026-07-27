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
        // NOTE: the platform intentionally does NOT create the `users` table here.
        // A host app almost always already owns its users, so imposing one would
        // collide. Greenfield apps publish the optional users migration
        // (`vendor:publish --tag=cbox-id-users-migration`); apps with existing
        // users point `cbox-id.models.user` / `cbox-id.tables.users` at their own.
        // These tables only reference `user_id` by value (indexed, no FK), so they
        // integrate with whatever user store the host provides.
        Schema::create('identities', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('user_id', 26)->index();
            $table->string('provider');
            $table->string('subject');
            $table->string('connection_id', 26)->nullable();
            $table->json('raw')->default(JsonDefault::emptyObject());
            $table->timestamps();

            // Scoped by connection: the same subject asserted through two different
            // SSO connections is two distinct identities (cross-tenant isolation).
            $table->unique(['environment_id', 'provider', 'subject', 'connection_id']);
        });

        Schema::create('auth_sessions', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('user_id', 26)->index();
            $table->string('organization_id', 26)->nullable();
            $table->string('ip')->nullable();
            $table->text('user_agent')->nullable();
            $table->json('amr')->default(JsonDefault::emptyArray());
            $table->timestamp('last_active_at')->nullable();
            $table->timestamp('expires_at');
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_sessions');
        Schema::dropIfExists('identities');
    }
};
