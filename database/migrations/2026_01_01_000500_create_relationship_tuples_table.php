<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('relationship_tuples', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->ulid('organization_id');
            // EXPLICIT LENGTHS, NOT THE varchar(255) DEFAULT.
            //
            // All seven columns below are covered by one unique index, and InnoDB caps
            // an index key at 3072 bytes. utf8mb4 budgets 4 bytes per character, so the
            // framework default made this key 26*4 + 6*255*4 = 6224 bytes and MySQL
            // refused the table outright (error 1071). Postgres and SQLite have no such
            // limit, which is why it was never noticed.
            //
            // The lengths are spelled out per column rather than pulled from a shared
            // constant on purpose: a migration is a historical record, and a constant
            // that someone later widens would silently give new installs a different
            // schema from every existing one.
            //
            // Budget: 104 + 256 + 512 + 256 + 256 + 512 + 256 = 2152 bytes.
            // A Zanzibar tuple is (type:id)#relation@(type:id#relation) — the types and
            // relations are short vocabulary words ('doc', 'viewer', 'member') and the
            // ids are ULIDs (26) or slugs, so this is many times the real ceiling.
            $table->string('object_type', 64);
            $table->string('object_id', 128);
            $table->string('relation', 64);
            $table->string('subject_type', 64);
            $table->string('subject_id', 128);
            $table->string('subject_relation', 64)->nullable();
            $table->timestamps();

            $table->unique([
                'organization_id', 'object_type', 'object_id', 'relation',
                'subject_type', 'subject_id', 'subject_relation',
            ], 'relationship_tuples_unique');
            // Named explicitly: the generated name would be 72 characters, over MySQL's
            // 64-byte identifier limit (error 1059) and over Postgres's 63, where it is
            // silently truncated instead — so the two engines disagreed on what this
            // index is even called.
            $table->index(
                ['organization_id', 'object_type', 'object_id', 'relation'],
                'relationship_tuples_org_object_relation_index',
            );
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('relationship_tuples');
    }
};
