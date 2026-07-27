<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('audit_logs', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            // The hash chain is per (environment, scope). Without the environment the
            // '__system__' scope was ONE global chain shared by every tenant — operator
            // and environment-level entries from unrelated customers interleaved in it,
            // and every writer contended on the same chain head.
            // NOT nullable, and defaulted to the platform sentinel. SQL treats NULLs as
            // distinct in a unique index, so a nullable column made the
            // (environment_id, scope, sequence) key silently inert for every entry
            // recorded outside an environment — the account plane restarted its chain on
            // every write. A sentinel makes the constraint real.
            //
            // EXPLICIT LENGTH: `environment_id` leads five indexes, one of which
            // (`audit_logs_env_org_target_seq_index`, added later) also covers
            // `target_type` and `target_id`. At the framework's varchar(255) default
            // that key is 4*255 + 26*4 + 4*255 + 4*255 + 8 = 3172 bytes, over InnoDB's
            // 3072-byte cap, and MySQL refused it (error 1071). The value is an
            // environment ULID (26) or the '__platform__' sentinel (12).
            $table->string('environment_id', 64)->default('__platform__')->index();
            $table->string('scope');                 // organization key, or '__system__'
            $table->ulid('organization_id')->nullable();
            $table->unsignedBigInteger('sequence');
            $table->string('actor_type');
            $table->string('actor_id')->nullable();
            $table->string('action')->index();
            // Also in that composite key; a target type is a short vocabulary word
            // ('user', 'session', 'organization'). `target_id` deliberately keeps the
            // full 255 — it holds an email address on invite/verification entries, and
            // RFC 5321 allows 254 characters. Key budget: 256 + 104 + 256 + 1020 + 8
            // = 1644 bytes.
            $table->string('target_type', 64)->nullable();
            $table->string('target_id')->nullable();
            $table->json('context');
            $table->string('ip')->nullable();
            $table->char('prev_hash', 64);
            $table->char('hash', 64);
            $table->timestamp('recorded_at');

            // One entry per position per chain, and the chain is environment-scoped.
            // (The former duplicate index on the same columns is gone — a unique index
            // already serves those reads, and the second B-tree was pure write
            // amplification on the highest-write table in the system.)
            $table->unique(['environment_id', 'scope', 'sequence']);

            // The console reads: newest-first within an org.
            $table->index(['environment_id', 'organization_id', 'sequence']);
        });

        Schema::create('audit_checkpoints', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            // A checkpoint anchors ONE chain, and a chain is per (environment, scope) —
            // so the checkpoint carries the environment too, or one tenant's checkpoint
            // would appear to anchor another's chain.
            // Same column, same width as `audit_logs.environment_id` above — a
            // checkpoint that could not store an id its chain can is a silent trap.
            $table->string('environment_id', 64)->default('__platform__')->index();
            $table->string('scope')->index();
            $table->ulid('organization_id')->nullable();
            $table->unsignedBigInteger('up_to_sequence');
            $table->char('root_hash', 64);
            $table->text('signature');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('audit_checkpoints');
        Schema::dropIfExists('audit_logs');
    }
};
