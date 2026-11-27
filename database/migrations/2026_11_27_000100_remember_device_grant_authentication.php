<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // No backfill: an approval timestamp cannot establish how the user signed in.
        Schema::table('device_codes', function (Blueprint $table): void {
            $table->unsignedInteger('auth_time')->nullable();
            $table->json('amr')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('device_codes', function (Blueprint $table): void {
            $table->dropColumn(['auth_time', 'amr']);
        });
    }
};
