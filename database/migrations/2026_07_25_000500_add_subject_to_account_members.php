<?php

declare(strict_types=1);

use Cbox\Id\Platform\DatabaseAccountMembers;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The account member's subject in the platform-root environment ("tenant 1") — the
 * credential of record from here on.
 *
 * Before this, an account member was a second, parallel credential store: its own
 * password column, its own sign-in path, no SSO, no passkeys, no password policy. The
 * subject it now points at is an ordinary one, so all of that applies to account members
 * for free. See docs/core-concepts/unified-account-identity.md.
 *
 * Nullable, and unique when set. Null means "not linked": the very first install
 * provisions an account before a platform root exists, and there is nowhere for the
 * subject to live yet. {@see DatabaseAccountMembers::verifyPassword()}
 * treats that case as the bootstrap it is and falls back to the local hash, rather than
 * locking the founder out of the deployment they are creating.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('account_members', function (Blueprint $table): void {
            $table->string('subject_id', 26)->nullable()->after('account_id')->unique();
        });
    }

    public function down(): void
    {
        Schema::table('account_members', function (Blueprint $table): void {
            $table->dropUnique(['subject_id']);
            $table->dropColumn('subject_id');
        });
    }
};
