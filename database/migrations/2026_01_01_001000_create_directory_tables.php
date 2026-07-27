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
        Schema::create('directories', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('organization_id', 26)->index();
            $table->string('name');
            $table->string('bearer_token_hash')->unique();
            $table->string('status')->default('active');
            $table->json('mappings')->default(JsonDefault::emptyObject());
            $table->timestamps();
        });

        Schema::create('directory_users', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('directory_id', 26)->index();
            $table->string('external_id');
            $table->json('resource');
            $table->string('user_id', 26)->nullable();
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
