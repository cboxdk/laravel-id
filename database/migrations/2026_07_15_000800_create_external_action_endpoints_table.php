<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // External hook endpoints: customer HTTPS URLs the platform calls
        // synchronously at a hook point. The per-endpoint HMAC signing secret is
        // stored sealed (SecretBox); the raw value is shown once at registration.
        Schema::create('external_action_endpoints', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->ulid('organization_id')->nullable()->index();
            $table->string('hook_point');
            $table->string('url');
            $table->text('secret_encrypted');
            $table->string('status')->default('active'); // active | paused
            $table->timestamps();

            // The pipeline looks up active endpoints per hook point (env-scoped). Named
            // explicitly: the generated name is exactly 64 characters — inside MySQL's
            // limit by one byte, but one over Postgres's 63, so Postgres truncated it
            // and the same index carried a different name on each engine.
            $table->index(
                ['environment_id', 'hook_point', 'status'],
                'external_action_endpoints_env_hook_status_index',
            );
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('external_action_endpoints');
    }
};
