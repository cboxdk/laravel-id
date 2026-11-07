<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('role_grant_subject_locks', function (Blueprint $table): void {
            // Subjects may come from a host resolver rather than the built-in users table.
            $table->string('environment_id', 64);
            $table->string('subject_id', 64);
            $table->primary(['environment_id', 'subject_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('role_grant_subject_locks');
    }
};
