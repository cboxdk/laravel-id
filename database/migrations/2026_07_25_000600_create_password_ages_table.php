<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

/**
 * When each subject's password was last set — the clock `AuthPolicy::maxAgeDays` runs
 * against.
 *
 * Its own table rather than a column on `users`, for the same reason as
 * `password_change_requirements`: the users table is HOST-OWNED and configurable, and a
 * library must not add columns to a table it does not own.
 *
 * It holds NO hash. `password_history` already stores hashes, and its most recent row's
 * timestamp would have answered this question — but only when the tenant has reuse
 * history switched on. Writing a hash the tenant did not ask us to keep, purely to date
 * it, is not a trade worth making for a column that could just be a timestamp.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('password_ages', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('user_id', 26);
            $table->timestamp('changed_at');
            $table->timestamps();

            $table->unique(['environment_id', 'user_id']);
        });

        // Every existing subject starts the clock NOW rather than at an unknown past
        // date. The alternative — treating "no row" as "never expires" — would mean
        // maxAgeDays silently never applied to anyone who predated it, which is the
        // failure mode this whole batch exists to stop. Starting the clock at the
        // upgrade is the standard behaviour and the one an operator can reason about.
        $usersTable = config('cbox-id.tables.users');

        if (! is_string($usersTable) || ! Schema::hasTable($usersTable) || ! Schema::hasColumn($usersTable, 'password')) {
            return;
        }

        $hasEnvironment = Schema::hasColumn($usersTable, 'environment_id');
        $now = now();

        DB::table($usersTable)
            ->whereNotNull('password')
            ->orderBy('id')
            ->chunk(500, function ($users) use ($hasEnvironment, $now): void {
                $rows = [];

                foreach ($users as $user) {
                    $environmentId = $hasEnvironment ? ($user->environment_id ?? null) : null;

                    if (! is_string($environmentId) || $environmentId === '') {
                        continue;
                    }

                    $rows[] = [
                        'id' => (string) Str::ulid(),
                        'environment_id' => $environmentId,
                        'user_id' => (string) $user->id,
                        'changed_at' => $now,
                        'created_at' => $now,
                        'updated_at' => $now,
                    ];
                }

                if ($rows !== []) {
                    DB::table('password_ages')->insert($rows);
                }
            });
    }

    public function down(): void
    {
        Schema::dropIfExists('password_ages');
    }
};
