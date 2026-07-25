<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * A standing requirement for a subject to change their password at next sign-in, plus
 * the expiry of an administratively-issued temporary password.
 *
 * Its own table rather than a column on `users`: the users table is HOST-OWNED and
 * configurable ({@see config('cbox-id.tables.users')}) so an app can map the platform
 * onto its existing users — a library must not add columns to a table it does not own.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('password_change_requirements', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->ulid('user_id');

            // When the temporary password stops working entirely. Null = the password
            // is permanent but a change is still required at next sign-in.
            $table->timestamp('expires_at')->nullable();

            // Who imposed it, for the audit trail the console surfaces.
            $table->string('set_by_type')->nullable();
            $table->string('set_by_id')->nullable();

            $table->timestamps();

            // One standing requirement per subject; re-issuing replaces it.
            $table->unique(['environment_id', 'user_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('password_change_requirements');
    }
};
