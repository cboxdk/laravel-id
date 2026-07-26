<?php

declare(strict_types=1);

use Cbox\Id\Directory\Models\DirectoryUser;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

/**
 * Give `directory_users` real, indexable columns for the two SCIM attributes RFC 7643
 * defines as `caseExact: false` — `userName` and the primary email.
 *
 * Both used to be compared straight out of the `resource` JSON blob, which made
 * equality depend entirely on the database's collation. On MySQL's default `_ci`
 * collation that happened to be case-insensitive and correct; on PostgreSQL it is
 * case-SENSITIVE, so an IdP's pre-provision lookup for `Dana.Rivera@corp.com` matched
 * nothing, the create-side uniqueness check missed as well, and a duplicate directory
 * user plus a duplicate subject were provisioned for one person.
 *
 * Why a column rather than `LOWER(resource->>'userName')` in the predicate: there is no
 * index on the JSON path to defeat, but there is no index to USE either — every
 * existence check was already a full scan of the directory's rows, and an IdP performs
 * one per user on every import. A stored, lower-cased column plus a composite index
 * with `directory_id` turns that scan into a seek, and it is portable across every
 * driver the package supports (no functional-index or generated-column syntax).
 *
 * The index is deliberately NOT unique: pre-existing case-variant duplicates would fail
 * the migration outright, and a unique violation would surface to the IdP as a 500
 * instead of the SCIM 409 `uniqueness` the application layer already returns.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('directory_users', function (Blueprint $table): void {
            $table->string('user_name_lower')->nullable()->after('external_id');
            $table->string('email_lower')->nullable()->after('user_name_lower');

            $table->index(['directory_id', 'user_name_lower']);
            $table->index(['directory_id', 'email_lower']);
        });

        $this->backfill();
    }

    public function down(): void
    {
        Schema::table('directory_users', function (Blueprint $table): void {
            $table->dropIndex(['directory_id', 'user_name_lower']);
            $table->dropIndex(['directory_id', 'email_lower']);
            $table->dropColumn(['user_name_lower', 'email_lower']);
        });
    }

    /**
     * Populate the new columns from the stored SCIM resource. Done in PHP over the
     * query builder rather than in SQL so it is identical on every driver, and outside
     * Eloquent so the environment scope cannot hide rows from the backfill.
     */
    private function backfill(): void
    {
        DB::table('directory_users')
            ->select(['id', 'resource'])
            ->orderBy('id')
            ->chunk(500, function (iterable $rows): void {
                foreach ($rows as $row) {
                    $resource = json_decode(is_string($row->resource) ? $row->resource : '', true);
                    $resource = is_array($resource) ? $resource : [];

                    DB::table('directory_users')->where('id', $row->id)->update([
                        'user_name_lower' => $this->normalize($resource['userName'] ?? null),
                        'email_lower' => $this->normalize($resource['email'] ?? null),
                    ]);
                }
            });
    }

    /**
     * Mirrors {@see DirectoryUser::normalize()}; kept local so
     * a later refactor of the model cannot silently change what this migration wrote.
     */
    private function normalize(mixed $value): ?string
    {
        if (! is_string($value)) {
            return null;
        }

        $value = trim($value);

        return $value === '' ? null : Str::lower($value);
    }
};
