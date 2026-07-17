<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Account members carry a role (the buyer plane's RBAC) and an environment-access
 * scope. `role` defaults to the least-privileged 'viewer' — deny-by-default, so a
 * member created without an explicit role can never accidentally hold power. The
 * account's first member (its owner) is created with 'owner' explicitly.
 *
 * `all_environments` true means the member reaches every environment the account
 * owns; false pins them to the environments listed in account_member_environments
 * (Stripe-style prod-vs-test developer access).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('account_members', function (Blueprint $table): void {
            $table->string('role')->default('viewer')->after('name');
            $table->boolean('all_environments')->default(true)->after('role');
        });
    }

    public function down(): void
    {
        Schema::table('account_members', function (Blueprint $table): void {
            $table->dropColumn(['role', 'all_environments']);
        });
    }
};
