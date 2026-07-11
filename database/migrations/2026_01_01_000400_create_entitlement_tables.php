<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('entitlements', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('organization_id');
            $table->string('key');
            $table->json('value');
            $table->string('mode');
            $table->string('source');
            $table->string('source_ref')->nullable();
            $table->unsignedInteger('version');
            $table->timestamp('effective_at')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamps();

            $table->unique(['organization_id', 'key']);
        });

        Schema::create('entitlement_history', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('organization_id');
            $table->string('key');
            $table->json('value')->nullable();
            $table->string('source');
            $table->string('source_ref')->nullable();
            $table->unsignedInteger('version');
            $table->string('change');
            $table->timestamp('recorded_at');

            $table->index(['organization_id', 'key']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('entitlement_history');
        Schema::dropIfExists('entitlements');
    }
};
