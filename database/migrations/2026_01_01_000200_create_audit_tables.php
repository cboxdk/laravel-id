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
            $table->string('environment_id')->default('__platform__')->index();
            $table->string('scope');                 // organization key, or '__system__'
            $table->ulid('organization_id')->nullable();
            $table->unsignedBigInteger('sequence');
            $table->string('actor_type');
            $table->string('actor_id')->nullable();
            $table->string('action')->index();
            $table->string('target_type')->nullable();
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
            $table->string('environment_id')->default('__platform__')->index();
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
