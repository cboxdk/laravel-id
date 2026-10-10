<?php

declare(strict_types=1);

use Cbox\Id\Identity\ValueObjects\AuthPolicy;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The environment-wide half of the authentication policy: which sign-in methods the
 * environment offers, how long its sessions last, and whether it uses a bot challenge.
 *
 * Every default is TODAY'S BEHAVIOUR, so an environment that existed before this migration
 * keeps exactly the doors it had: passkeys and magic links on, the bot challenge on wherever
 * the deployment has one, and both session lengths null — "the deployment's own".
 *
 * Columns on the existing table rather than a table of their own, because they are read on
 * the same paths as the rest of the policy and by the same resolver, and a second table
 * would be a second query on every sign-in for five values. An organization's override row
 * carries them too, unused: {@see AuthPolicy::tightenedWith()}
 * keeps the baseline's.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('auth_policies', function (Blueprint $table): void {
            $table->boolean('passkeys')->default(true);
            $table->boolean('magic_link')->default(true);
            $table->unsignedInteger('session_idle_minutes')->nullable();
            $table->unsignedInteger('session_absolute_minutes')->nullable();
            $table->boolean('bot_challenge')->default(true);
        });
    }

    public function down(): void
    {
        Schema::table('auth_policies', function (Blueprint $table): void {
            $table->dropColumn(['passkeys', 'magic_link', 'session_idle_minutes', 'session_absolute_minutes', 'bot_challenge']);
        });
    }
};
