<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('membership_directory_revisions', function (Blueprint $table): void {
            $table->string('organization_id', 64)->primary();
            $table->unsignedBigInteger('revision')->default(0);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('membership_directory_revisions');
    }
};
