<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('events', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('type')->index();
            $table->string('organization_id', 26)->nullable()->index();
            $table->json('payload');
            $table->timestamp('occurred_at');
            $table->timestamp('dispatched_at')->nullable()->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('events');
    }
};
