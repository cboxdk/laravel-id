<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * An account's home in the platform-root environment ("tenant 1").
 *
 * Account members are ordinary subjects there rather than a second credential store, so
 * every account needs an organization to hold its people — and, once it does, account
 * SSO is an ordinary connection on that organization instead of a parallel federation
 * stack. See docs/core-concepts/unified-account-identity.md.
 *
 * Nullable while the app-side cutover lands: an account provisioned before this column
 * existed has no organization yet, and the resolver treats null as "not yet homed"
 * rather than inventing one.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('accounts', function (Blueprint $table): void {
            $table->ulid('organization_id')->nullable()->after('id')->unique();
        });
    }

    public function down(): void
    {
        Schema::table('accounts', function (Blueprint $table): void {
            $table->dropUnique(['organization_id']);
            $table->dropColumn('organization_id');
        });
    }
};
