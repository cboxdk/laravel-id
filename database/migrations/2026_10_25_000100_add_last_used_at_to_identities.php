<?php

declare(strict_types=1);

use Cbox\Id\Identity\DatabaseSubjects;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * When a linked sign-in identity last signed somebody in.
 *
 * A person looking at "Sign in with Google — linked" on their own account page is asking
 * two questions, and the table could answer only one of them: THAT it is linked
 * (`created_at`), never WHETHER IT IS STILL BEING USED. The second is the one that matters
 * when deciding to disconnect something, and the one that makes a link nobody remembers
 * making stand out — a Google sign-in last used yesterday on an account whose owner signs
 * in with a passkey is worth a second look.
 *
 * Stamped by {@see DatabaseSubjects::resolveFederated()} when the
 * identity resolves a sign-in, and when a first sign-in creates it. Nullable, with no
 * backfill: an identity linked before this column existed has simply not been seen since,
 * and inventing a date for it (its `created_at`, say) would be a claim about a sign-in
 * that may never have happened.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('identities', function (Blueprint $table): void {
            $table->timestamp('last_used_at')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('identities', function (Blueprint $table): void {
            $table->dropColumn('last_used_at');
        });
    }
};
