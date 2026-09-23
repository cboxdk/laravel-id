<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * `tenant_assignable` on ROLES — the flag permissions have had since 2026-07-17.
 *
 * False marks a STAFF role: one the application vendor hands to its own support people
 * and administrators. A tenant administrator must never be offered it, nor be able to
 * grant it by naming its id, because a staff role usually carries rights across every
 * customer of the app (see `Roles::assignEverywhere()`), and a customer handing that to
 * one of their own members would be a privilege escalation out of their tenancy.
 *
 * Default TRUE, so every role that exists today keeps behaving exactly as it did: the
 * column only narrows what a role an app (or an environment administrator) explicitly
 * marks as staff-only can be used for.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('roles', function (Blueprint $table): void {
            $table->boolean('tenant_assignable')->default(true)->after('description');
        });
    }

    public function down(): void
    {
        Schema::table('roles', function (Blueprint $table): void {
            $table->dropColumn('tenant_assignable');
        });
    }
};
