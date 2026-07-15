<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Downstream provisioning targets (the outbound mirror of `directories`).
        Schema::create('provisioning_connections', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->ulid('organization_id')->nullable()->index();
            $table->string('name');
            $table->string('base_url');
            $table->string('auth_scheme')->default('bearer');
            $table->text('auth_secret_encrypted');
            $table->json('auth_config')->nullable();
            $table->json('attribute_mapping');
            $table->json('scope');
            $table->string('deprovision_policy')->default('deactivate');
            $table->string('status')->default('active')->index();
            // Circuit-breaker health.
            $table->unsignedInteger('consecutive_failures')->default(0);
            $table->timestamp('circuit_opened_at')->nullable();
            $table->timestamp('last_success_at')->nullable();
            $table->text('last_error')->nullable();
            $table->timestamps();
        });

        // The platform user ↔ remote SCIM resource mapping (SCIM statefulness).
        Schema::create('provisioned_resources', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->ulid('connection_id')->index();
            $table->string('user_id')->index();
            $table->string('external_id');
            $table->string('remote_id')->nullable();
            $table->string('state')->default('active');
            $table->timestamp('last_synced_at')->nullable();
            $table->timestamps();

            // At most one mirror per (environment, connection, user).
            $table->unique(['environment_id', 'connection_id', 'user_id']);
        });

        // The durable outbox of pending SCIM operations.
        Schema::create('provisioning_operations', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->ulid('connection_id')->index();
            $table->string('user_id')->index();
            $table->string('type');
            $table->json('payload');
            $table->string('status')->default('pending')->index();
            $table->unsignedInteger('attempt')->default(0);
            $table->unsignedInteger('response_code')->nullable();
            $table->timestamp('next_attempt_at')->nullable()->index();
            $table->timestamp('delivered_at')->nullable();
            $table->text('last_error')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('provisioning_operations');
        Schema::dropIfExists('provisioned_resources');
        Schema::dropIfExists('provisioning_connections');
    }
};
