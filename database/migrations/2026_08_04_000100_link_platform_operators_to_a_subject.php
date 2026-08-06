<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Point a platform operator at an ordinary subject, the way an account member already
 * does.
 *
 * Operators are the last credential store in the platform. Subjects carry the whole
 * authentication estate — password policy, breach checks, lockout, TOTP, passkeys,
 * step-up, session revocation — and an operator has none of it, because it was never
 * given any: `platform_operators` holds an email and a bcrypt hash and nothing else.
 * That is the weakest door in the product guarding the widest reach, and it is weakest
 * precisely because it is separate.
 *
 * Account members went through this already — `account_members.subject_id` exists and
 * `verifyPassword()` asks the subject, keeping the local hash only for the bootstrap
 * window before a platform root exists. This is the same change for the same reason, and
 * the local hash stays for the same narrow case rather than being dropped here: a column
 * removed before every row has a subject is a deployment that cannot authenticate.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('platform_operators', function (Blueprint $table): void {
            // Nullable, because an operator created before a platform root existed has
            // nowhere for a subject to live. Backfilled on next sign-in rather than in a
            // data migration: the subject needs a password, and this table only holds a
            // hash of one.
            $table->string('subject_id', 26)->nullable()->after('id');

            // The lookup every request makes once the session is keyed on the subject.
            $table->index('subject_id', 'platform_operators_subject_id_index');
        });
    }

    public function down(): void
    {
        Schema::table('platform_operators', function (Blueprint $table): void {
            // Named explicitly — an inferred name has differed from the created one on at
            // least one engine here, and the rollback then failed on an index that "did
            // not exist".
            $table->dropIndex('platform_operators_subject_id_index');
            $table->dropColumn('subject_id');
        });
    }
};
