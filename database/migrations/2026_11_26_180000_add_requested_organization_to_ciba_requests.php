<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('ciba_requests', function (Blueprint $table): void {
            // Null preserves legacy approval-time selection, including outstanding requests.
            $table->string('requested_organization_id', 26)->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('ciba_requests', function (Blueprint $table): void {
            $table->dropColumn('requested_organization_id');
        });
    }
};
