<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * A monotonic "security stamp" for account members. It is stamped into the session
 * at sign-in and re-checked on every request; bumping it (on password reset, and
 * any future credential change) instantly invalidates every existing session AND
 * any outstanding password-reset link bound to the old value — one mechanism for
 * both single-use reset links and "log out everywhere on reset".
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('account_members', function (Blueprint $table): void {
            $table->unsignedInteger('session_version')->default(0)->after('status');
        });
    }

    public function down(): void
    {
        Schema::table('account_members', function (Blueprint $table): void {
            $table->dropColumn('session_version');
        });
    }
};
