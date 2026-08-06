<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Attach a subject to every operator that predates the unification.
 *
 * The previous migration made `platform_operators.subject_id` nullable and left the
 * attaching to `verifyPassword()`: the local bcrypt hash stayed the credential, and the
 * subject was created on that operator's NEXT successful sign-in — the only moment the
 * plaintext is available to seed one. That was correct while a sign-in existed that
 * verified against the local hash.
 *
 * It does not any more. Operator authority became a permission on the ordinary sign-in,
 * and the separate operator login form — the only caller that reached the bootstrap
 * window — went with it. So on a deployment upgraded from before the unification, every
 * existing operator has `subject_id = NULL`, no subject to sign in as, and no door left
 * that consults their hash. They are locked out of the deployment they run, by an upgrade
 * that reports success.
 *
 * The plaintext is gone, but the hash is not, and it does not need to be re-derived: both
 * tables hash with the configured driver and both models carry the `hashed` cast, which
 * passes an already-hashed value through untouched. So the credential MOVES. The operator
 * signs in at the one door with exactly the password they had.
 *
 * Deliberately a migration rather than a command. A command is a step someone has to know
 * about, and the failure mode for not knowing is that nobody can administer the platform —
 * discovered after the deploy, by the person who can no longer fix it.
 *
 * Written as raw queries, no models: models carry global scopes (subjects are
 * environment-owned) and drift with the codebase, and a migration has to keep meaning what
 * it meant on the day it ran.
 */
return new class extends Migration
{
    public function up(): void
    {
        // Subjects are environment-owned, so there has to be somewhere to put them. A
        // deployment with no platform root has not been installed yet; its operators go
        // through `create()`, which attaches on the spot.
        $root = DB::table('environments')->where('is_default', true)->value('id');

        if (! is_string($root) || $root === '') {
            return;
        }

        $operators = DB::table('platform_operators')
            ->whereNull('subject_id')
            ->get(['id', 'email', 'name', 'password', 'created_at']);

        foreach ($operators as $operator) {
            $email = is_string($operator->email) ? $operator->email : '';

            if ($email === '') {
                continue;
            }

            // Reuse before create. An operator who is also an account member already has a
            // subject at this address, and giving them a second one is the split in the id
            // space that this whole change exists to end. Their existing password is NOT
            // touched — it is the one they actually use, and the operator hash may be the
            // older of the two.
            $existing = DB::table('users')
                ->where('environment_id', $root)
                ->where('email', $email)
                ->value('id');

            if (is_string($existing) && $existing !== '') {
                DB::table('platform_operators')
                    ->where('id', $operator->id)
                    ->update(['subject_id' => $existing]);

                continue;
            }

            // No hash means no credential to carry over — an operator provisioned for SSO
            // or one whose row was written by hand. Left unattached rather than given a
            // subject nobody can authenticate as, which would look repaired and not be.
            if (! is_string($operator->password) || $operator->password === '') {
                continue;
            }

            $subjectId = (string) Str::ulid();

            DB::table('users')->insert([
                'id' => $subjectId,
                'environment_id' => $root,
                'email' => $email,
                'name' => is_string($operator->name) ? $operator->name : null,
                // The hash moves as-is. Re-hashing is impossible without the plaintext, and
                // unnecessary: it was produced by the same driver this subject verifies with.
                'password' => $operator->password,
                'status' => 'active',
                // NOT marked verified. Nothing here proves control of the address — the
                // operator table never asked — and claiming otherwise would hand a
                // confirmed address to a step-up gate that relies on it meaning something.
                'email_verified_at' => null,
                'created_at' => $operator->created_at ?? now(),
                'updated_at' => now(),
            ]);

            DB::table('platform_operators')
                ->where('id', $operator->id)
                ->update(['subject_id' => $subjectId]);
        }
    }

    /**
     * Unlink, but do not delete.
     *
     * Rolling back cannot know which subjects this migration created and which it merely
     * pointed at — an operator who was already an account member shares one, and deleting
     * it would delete a person's account. Unlinking restores the column's previous state
     * and leaves a reversible mess rather than an irreversible one.
     */
    public function down(): void
    {
        DB::table('platform_operators')->update(['subject_id' => null]);
    }
};
