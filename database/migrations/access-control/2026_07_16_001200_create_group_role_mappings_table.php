<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Bridges the SCIM gap: maps a customer's directory GROUP (e.g. "Engineering") onto
 * a Cbox ID ROLE (e.g. "Developer"). Membership in the group grants the role via the
 * `pushed` assignment source; `priority` orders mappings for display and for future
 * single-role resolution (the model assigns the union today). The directory supplies
 * WHO is in a group; this table supplies WHAT that means.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('group_role_mappings', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->ulid('organization_id')->index();
            $table->ulid('group_id');   // directory_groups.id
            $table->ulid('role_id');    // roles.id
            $table->integer('priority')->default(0);
            $table->timestamps();

            $table->unique(['organization_id', 'group_id', 'role_id']);
            $table->index('group_id');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('group_role_mappings');
    }
};
