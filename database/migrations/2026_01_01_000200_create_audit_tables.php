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

            $table->unique(['scope', 'sequence']);   // one entry per position per chain
            $table->index(['scope', 'sequence']);
        });

        Schema::create('audit_checkpoints', function (Blueprint $table): void {
            $table->ulid('id')->primary();
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
