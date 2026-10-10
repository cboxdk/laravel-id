<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Fine-grained authorization: one model row per environment, and its tuples.
 *
 * Two indexes carry every query the evaluator makes, so each step of a check is one index
 * range read however many tuples the environment holds:
 *
 *  - FORWARD, the unique key — `(environment, resource type, resource id, relation, …)`:
 *    "who is named on document:readme#viewer" and "is alice named there" (check,
 *    list-subjects), and the identity a duplicate write collides on;
 *  - REVERSE — `(environment, subject type, subject id, subject relation, resource type,
 *    relation)`: "what names user:alice" and "which documents point at folder:handbook as
 *    their parent" (list-resources, tuple-to-userset walked backwards).
 *
 * Column widths are the relationship_tuples ones, for the same reason: the unique key's
 * seven columns must fit InnoDB's 3072-byte key limit at four bytes a character
 * (104 + 256 + 512 + 256 + 256 + 512 + 256 = 2152).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('fga_stores', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->unique();
            $table->unsignedBigInteger('revision')->default(0);
            $table->string('revision_tag', 32);
            $table->longText('schema_source')->nullable();
            $table->longText('schema')->nullable();
            $table->string('schema_hash', 64)->nullable();
            $table->unsignedInteger('schema_version')->default(0);
            $table->timestamp('schema_updated_at')->nullable();
            $table->timestamps();
        });

        Schema::create('fga_tuples', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26);
            $table->string('resource_type', 64);
            $table->string('resource_id', 128);
            $table->string('relation', 64);
            $table->string('subject_type', 64);
            $table->string('subject_id', 128);
            $table->string('subject_relation', 64)->default('');
            $table->unsignedBigInteger('created_revision');
            $table->timestamp('created_at')->nullable();

            $table->unique([
                'environment_id', 'resource_type', 'resource_id', 'relation',
                'subject_type', 'subject_id', 'subject_relation',
            ], 'fga_tuples_forward_unique');
            $table->index([
                'environment_id', 'subject_type', 'subject_id', 'subject_relation',
                'resource_type', 'relation',
            ], 'fga_tuples_reverse_index');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('fga_tuples');
        Schema::dropIfExists('fga_stores');
    }
};
