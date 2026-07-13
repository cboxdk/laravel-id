<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('organizations', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->string('name');
            $table->string('slug')->unique();
            $table->ulid('parent_id')->nullable()->index();
            $table->string('type')->default('customer');
            $table->string('status')->default('active');
            $table->json('settings')->default('{}');
            $table->timestamps();
        });

        Schema::create('organization_closure', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->ulid('ancestor_id');
            $table->ulid('descendant_id');
            $table->unsignedInteger('depth');

            $table->unique(['ancestor_id', 'descendant_id']);
            $table->index('descendant_id');
        });

        Schema::create('memberships', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->ulid('organization_id')->index();
            $table->ulid('user_id');
            $table->string('role');
            $table->string('status')->default('active');
            $table->ulid('invited_by')->nullable();
            $table->timestamps();

            $table->unique(['organization_id', 'user_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('memberships');
        Schema::dropIfExists('organization_closure');
        Schema::dropIfExists('organizations');
    }
};
