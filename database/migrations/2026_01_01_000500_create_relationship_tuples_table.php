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
            $table->string('object_type');
            $table->string('object_id');
            $table->string('relation');
            $table->string('subject_type');
            $table->string('subject_id');
            $table->string('subject_relation')->nullable();
            $table->timestamps();

            $table->unique([
                'organization_id', 'object_type', 'object_id', 'relation',
                'subject_type', 'subject_id', 'subject_relation',
            ], 'relationship_tuples_unique');
            $table->index(['organization_id', 'object_type', 'object_id', 'relation']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('relationship_tuples');
    }
};
