<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('directories', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->ulid('organization_id')->index();
            $table->string('name');
            $table->string('bearer_token_hash')->unique();
            $table->string('status')->default('active');
            $table->json('mappings')->default('{}');
            $table->timestamps();
        });

        Schema::create('directory_users', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('directory_id')->index();
            $table->string('external_id');
            $table->json('resource');
            $table->ulid('user_id')->nullable();
            $table->boolean('active')->default(true);
            $table->timestamps();

            $table->unique(['directory_id', 'external_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('directory_users');
        Schema::dropIfExists('directories');
    }
};
