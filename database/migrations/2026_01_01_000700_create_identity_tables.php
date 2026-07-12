<?php

declare(strict_types=1);

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
            $table->ulid('id')->primary();
            $table->ulid('user_id')->index();
            $table->string('provider');
            $table->string('subject');
            $table->ulid('connection_id')->nullable();
            $table->json('raw')->default('{}');
            $table->timestamps();

            $table->unique(['provider', 'subject']);
        });

        Schema::create('auth_sessions', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('user_id')->index();
            $table->ulid('organization_id')->nullable();
            $table->string('ip')->nullable();
            $table->text('user_agent')->nullable();
            $table->json('amr')->default('[]');
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
