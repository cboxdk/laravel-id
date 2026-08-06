<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('roles', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('organization_id', 26)->nullable();
            $table->string('name');
            $table->string('description')->nullable();
            $table->timestamps();

            $table->unique(['organization_id', 'name']);
        });

        Schema::create('permissions', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('name')->unique();
            $table->string('description')->nullable();
            $table->timestamps();
        });

        Schema::create('role_permission', function (Blueprint $table): void {
            $table->string('role_id', 26);
            $table->string('permission_id', 26);

            $table->primary(['role_id', 'permission_id']);
            $table->index('permission_id');
        });

        Schema::create('role_assignments', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('organization_id', 26)->index();
            $table->string('user_id', 26);
            $table->string('role_id', 26);
            $table->string('source')->default('manual');
            $table->string('source_ref')->nullable();
            $table->timestamps();

            $table->unique(['organization_id', 'user_id', 'role_id']);
            $table->index(['user_id', 'organization_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('role_assignments');
        Schema::dropIfExists('role_permission');
        Schema::dropIfExists('permissions');
        Schema::dropIfExists('roles');
    }
};
