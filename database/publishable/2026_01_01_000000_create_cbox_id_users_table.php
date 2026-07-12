<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * OPTIONAL — the platform's canonical `users` table for greenfield installs.
 *
 * This is NOT loaded automatically. Publish it only when the host app does not
 * already have a users table:
 *
 *     php artisan vendor:publish --tag=cbox-id-users-migration
 *
 * Apps that already have users skip this and point `cbox-id.models.user` at
 * their own model (it must extend Cbox\Id\Identity\Models\User) and, if the
 * table is named differently, set `cbox-id.tables.users`.
 */
return new class extends Migration
{
    public function up(): void
    {
        $table = config('cbox-id.tables.users');
        $table = is_string($table) && $table !== '' ? $table : 'users';

        if (Schema::hasTable($table)) {
            return;
        }

        Schema::create($table, function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->string('email')->unique();
            $table->string('name')->nullable();
            $table->string('password')->nullable();
            $table->string('status')->default('active');
            $table->timestamp('email_verified_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        $table = config('cbox-id.tables.users');
        $table = is_string($table) && $table !== '' ? $table : 'users';

        Schema::dropIfExists($table);
    }
};
