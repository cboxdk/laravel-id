<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Schema;

/**
 * Move this package's password-reset tokens off the `password_reset_tokens` name.
 *
 * WHY
 *
 * Laravel's own `0001_01_01_000000_create_users_table` skeleton migration — present
 * in every freshly scaffolded application — creates a `password_reset_tokens` table
 * (`email` primary key, `token`, `created_at`). This package created one too, with a
 * completely different shape. Because the skeleton migration sorts first, a
 * greenfield `composer require cboxdk/laravel-id && php artisan migrate` died with
 * "table already exists" on the package's very first schema migration, on every
 * engine. That was the entire first-run experience for anyone who had not stripped
 * their skeleton, and the suite never saw it because the test harness publishes the
 * package's own users migration instead of Laravel's.
 *
 * The create migration now says `cbox_id_password_reset_tokens`; this carries an
 * existing installation across, rows and all.
 *
 * WHY IT IS SAFE
 *
 * The rename is guarded three ways, so it is a no-op on anything but the one case
 * it is for, and can be replayed:
 *
 *   1. If `cbox_id_password_reset_tokens` already exists there is nothing to do —
 *      that covers a fresh install (the create migration made it under the new
 *      name) and a re-run.
 *   2. If `password_reset_tokens` does not exist there is nothing to rename.
 *   3. If a `password_reset_tokens` DOES exist, it is renamed ONLY when it carries
 *      `environment_id` and `token_hash`. Laravel's skeleton table has neither, so a
 *      host that meanwhile added the skeleton migration keeps its own table
 *      untouched — this migration will never adopt, move or drop a table it did not
 *      create.
 *
 * Ordering: this runs after 2026_07_26_000100_convert_char_columns_to_varchar, which
 * lists the table under its OLD name. That is correct in both directions — an
 * upgrading database still has the old name when the conversion runs, and a fresh
 * one is created `varchar` by the create migration and needs no conversion. The
 * conversion is column-guarded (`id`, `environment_id`), so it likewise cannot touch
 * a skeleton `password_reset_tokens` it happens to find.
 */
return new class extends Migration
{
    private const FROM = 'password_reset_tokens';

    private const TO = 'cbox_id_password_reset_tokens';

    public function up(): void
    {
        if (Schema::hasTable(self::TO) || ! Schema::hasTable(self::FROM)) {
            return;
        }

        if (! $this->isOurs(self::FROM)) {
            return;
        }

        Schema::rename(self::FROM, self::TO);
    }

    public function down(): void
    {
        if (Schema::hasTable(self::FROM) || ! Schema::hasTable(self::TO)) {
            return;
        }

        Schema::rename(self::TO, self::FROM);
    }

    /**
     * Both columns are this package's; neither exists on Laravel's skeleton table.
     */
    private function isOurs(string $table): bool
    {
        return Schema::hasColumn($table, 'environment_id')
            && Schema::hasColumn($table, 'token_hash');
    }
};
