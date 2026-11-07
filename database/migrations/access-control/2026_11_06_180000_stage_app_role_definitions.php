<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('roles', function (Blueprint $table): void {
            $table->string('active_definition_version', 64)->nullable();
            $table->string('pending_definition_version', 64)->nullable();
            $table->json('pending_permission_keys')->nullable();
            $table->boolean('pending_tenant_assignable')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('roles', function (Blueprint $table): void {
            $table->dropColumn(['active_definition_version', 'pending_definition_version', 'pending_permission_keys', 'pending_tenant_assignable']);
        });
    }
};
