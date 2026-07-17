<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * App-declared roles & permissions (the manifest model). An app registers its own
 * roles + permissions with Cbox ID; they live in the SAME roles/permissions tables
 * as admin-defined org roles — distinguished by a non-null `client_id` and
 * `source = manifest` — so role assignments, the access checker and the token
 * issuer treat them uniformly. Dropping a declared role from a later manifest sets
 * `orphaned_at` rather than deleting it, so a bad deploy never silently revokes a
 * live assignment.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('roles', function (Blueprint $table): void {
            $table->string('client_id')->nullable()->after('organization_id')->index();
            $table->string('key')->nullable()->after('name');
            $table->string('source')->default('manual')->after('description'); // manual | manifest
            $table->timestamp('orphaned_at')->nullable();

            // Two different apps may each declare an "Admin" role, so name is only
            // unique within (org, app); a declared role is also addressable by its
            // stable (app, key) slug.
            $table->unique(['organization_id', 'client_id', 'name']);
            $table->unique(['client_id', 'key']);
        });

        // Replace the old (organization_id, name) unique now that (org, client, name)
        // supersedes it.
        Schema::table('roles', function (Blueprint $table): void {
            $table->dropUnique(['organization_id', 'name']);
        });

        Schema::table('permissions', function (Blueprint $table): void {
            $table->string('client_id')->nullable()->after('id')->index();
            $table->timestamp('orphaned_at')->nullable();

            // A permission key (feature:action) is unique per declaring app; org-level
            // permissions keep client_id null.
            $table->unique(['client_id', 'name']);
        });

        Schema::table('permissions', function (Blueprint $table): void {
            $table->dropUnique(['name']);
        });

        // The last-synced manifest per app — its version + content checksum, so a
        // re-sync with an unchanged manifest is a cheap no-op.
        Schema::create('app_manifests', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->string('client_id');
            $table->string('version')->nullable();
            $table->string('checksum');
            $table->timestamp('synced_at');
            $table->timestamps();

            $table->unique(['environment_id', 'client_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('app_manifests');

        Schema::table('permissions', function (Blueprint $table): void {
            $table->dropUnique(['client_id', 'name']);
            $table->unique('name');
            $table->dropColumn(['client_id', 'orphaned_at']);
        });

        Schema::table('roles', function (Blueprint $table): void {
            $table->unique(['organization_id', 'name']);
            $table->dropUnique(['organization_id', 'client_id', 'name']);
            $table->dropUnique(['client_id', 'key']);
            $table->dropColumn(['client_id', 'key', 'source', 'orphaned_at']);
        });
    }
};
