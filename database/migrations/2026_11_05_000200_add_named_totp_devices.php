<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('mfa_factors', function (Blueprint $table): void {
            // Slot zero preserves existing credentials and the singleton SMS constraint.
            $table->unsignedTinyInteger('slot')->default(0);
            $table->string('name', 120)->default('');
            $table->dropUnique(['user_id', 'type']);
            $table->unique(['user_id', 'type', 'slot']);
        });
    }

    public function down(): void
    {
        if (DB::table('mfa_factors')->select('user_id', 'type')->groupBy('user_id', 'type')->havingRaw('COUNT(*) > 1')->exists()) {
            throw new RuntimeException('Cannot roll back named authenticators while users have multiple credentials. No credentials were removed.');
        }
        Schema::table('mfa_factors', function (Blueprint $table): void {
            $table->dropUnique(['user_id', 'type', 'slot']);
            $table->unique(['user_id', 'type']);
            $table->dropColumn(['slot', 'name']);
        });
    }
};
