<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('webhook_endpoints', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('organization_id')->nullable()->index();
            $table->string('url');
            $table->text('secret_encrypted');
            $table->json('event_types');
            $table->string('status')->default('active');
            $table->timestamps();
        });

        Schema::create('webhook_deliveries', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('endpoint_id')->index();
            $table->string('event_type')->index();
            $table->json('payload');
            $table->unsignedInteger('attempt')->default(0);
            $table->string('status')->default('pending')->index();
            $table->unsignedInteger('response_code')->nullable();
            $table->timestamp('next_retry_at')->nullable()->index();
            $table->timestamp('delivered_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('webhook_deliveries');
        Schema::dropIfExists('webhook_endpoints');
    }
};
