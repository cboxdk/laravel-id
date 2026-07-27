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
        Schema::create('organizations', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('name');
            $table->string('slug');
            $table->string('parent_id', 26)->nullable()->index();
            $table->string('type')->default('customer');
            $table->string('status')->default('active');
            $table->json('settings')->default(JsonDefault::emptyObject());
            $table->timestamps();

            // Slugs are unique per environment, mirroring the users table's
            // (environment_id, email): the same slug may exist in two environments.
            $table->unique(['environment_id', 'slug']);
        });

        Schema::create('organization_closure', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('ancestor_id', 26);
            $table->string('descendant_id', 26);
            $table->unsignedInteger('depth');

            $table->unique(['ancestor_id', 'descendant_id']);
            $table->index('descendant_id');
        });

        Schema::create('memberships', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('organization_id', 26)->index();
            $table->string('user_id', 26);
            $table->string('role');
            $table->string('status')->default('active');
            $table->string('invited_by', 26)->nullable();
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
