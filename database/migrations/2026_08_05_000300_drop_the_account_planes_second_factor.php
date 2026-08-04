<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Kernel\Database\JsonDefault;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Remove the account plane's own second factor. There is one credential per person now,
 * and it is the subject's.
 *
 * WHY THESE TABLES ARE GOING RATHER THAN BEING MIGRATED. They were built on the premise
 * that an account member is a separate principal from a subject — "a SEPARATE subsystem
 * from operator and subject MFA", as the original migration put it, so that "one plane's
 * factor is never mistaken for another's". That premise is what the unified account
 * identity work removed: an account member IS an ordinary subject in the platform root,
 * and the member row is a lookup saying which account that subject belongs to.
 *
 * Once the deployment's one sign-in served the platform root, the account-plane factor
 * stopped being enforceable at all. A member holding an account TOTP signed in at
 * `/login` against their SUBJECT credential and reached the console with a password
 * alone; nothing on that path had any reason to consult a table keyed by member id. The
 * factor was not weakened by removing the door — it had already been bypassed by adding
 * one, and what remained was its appearance.
 *
 * A store that can still be written but is never checked is worse than no store. It reads
 * as protection in a schema diagram and in a security review, it accumulates secrets that
 * have to be sealed and rotated and disclosed in a breach, and the person who enrolled
 * against it believes they have a second factor. Deleting it states the truth the code
 * already had.
 *
 * WHERE A MEMBER'S SECOND FACTOR LIVES NOW: on their subject, through {@see Mfa}, enrolled
 * on the account security page and enforced by `PlatformAuth::attemptPassword()`, which
 * holds a subject with a confirmed TOTP at the challenge. That is the same factor, the
 * same enforcement and the same recovery codes every other person on the deployment gets.
 *
 * NO DATA IS CARRIED ACROSS, deliberately. A TOTP secret cannot be moved to a different
 * principal without the holder re-enrolling — the authenticator entry names the account
 * plane's issuer and label — and silently re-pointing a sealed secret would produce a
 * factor whose owner never agreed to it. Anyone who did enrol re-enrols on the account
 * security page; `down()` restores the tables, but it cannot restore the rows, and this
 * says so rather than implying a reversal it cannot perform.
 */
return new class extends Migration
{
    public function up(): void
    {
        // Order matters only for the foreign keys onto `account_members`; each of these
        // owns nothing, so dropping them frees the constraint rather than needing one.
        Schema::dropIfExists('account_webauthn_credentials');
        Schema::dropIfExists('account_mfa_recovery_codes');
        Schema::dropIfExists('account_mfa_factors');
    }

    /**
     * Rebuilt exactly as `2026_07_17_000170` and `2026_07_18_000100` left them — including
     * the varchar widths `2026_07_26_000100` converted them to, so a rollback lands on the
     * schema that migration produced rather than on the one before it.
     *
     * The rows do not come back. See the class docblock: a sealed TOTP secret belongs to
     * the principal it was enrolled against, and this migration deletes that principal's
     * credential store on purpose.
     */
    public function down(): void
    {
        Schema::create('account_mfa_factors', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('account_member_id', 26);
            $table->foreign('account_member_id')->references('id')->on('account_members')->cascadeOnDelete();
            $table->string('type');
            $table->text('secret_encrypted');
            $table->timestamp('confirmed_at')->nullable();
            $table->unsignedBigInteger('last_used_step')->nullable();
            $table->timestamps();

            $table->unique(['account_member_id', 'type']);
        });

        Schema::create('account_mfa_recovery_codes', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('account_member_id', 26);
            $table->foreign('account_member_id')->references('id')->on('account_members')->cascadeOnDelete();
            $table->string('code_hash');
            $table->timestamp('used_at')->nullable();
            $table->timestamps();

            $table->index('account_member_id');
        });

        Schema::create('account_webauthn_credentials', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('account_member_id', 26);
            $table->foreign('account_member_id')->references('id')->on('account_members')->cascadeOnDelete();
            $table->string('credential_id')->unique();
            $table->text('public_key');
            $table->unsignedBigInteger('sign_count')->default(0);
            $table->json('transports')->default(JsonDefault::emptyArray());
            $table->string('name')->nullable();
            $table->timestamps();

            $table->index('account_member_id');
        });
    }
};
