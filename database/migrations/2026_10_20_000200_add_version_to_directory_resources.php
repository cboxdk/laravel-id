<?php

declare(strict_types=1);

use Cbox\Id\Scim\Support\ScimETag;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * A revision counter on the two SCIM resource tables, so each resource carries an
 * entity-tag (RFC 7644 §3.14) that changes on EVERY write.
 *
 * `updated_at` cannot do this on its own: the column has one-second precision, so two
 * writes inside the same second would leave the tag unchanged and an `If-Match` taken
 * before the first would still pass after the second — the lost update ETags exist to
 * prevent. The counter is bumped by the models on every save that changes the row, and
 * by the group store whenever membership changes (a pivot write that never touches the
 * group row). See {@see ScimETag::forRevision()}.
 *
 * Every existing row starts at revision 1. A plain integer default, portable across
 * every supported engine.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('directory_users', function (Blueprint $table): void {
            $table->unsignedBigInteger('version')->default(1);
        });

        Schema::table('directory_groups', function (Blueprint $table): void {
            $table->unsignedBigInteger('version')->default(1);
        });
    }

    public function down(): void
    {
        Schema::table('directory_groups', function (Blueprint $table): void {
            $table->dropColumn('version');
        });

        Schema::table('directory_users', function (Blueprint $table): void {
            $table->dropColumn('version');
        });
    }
};
