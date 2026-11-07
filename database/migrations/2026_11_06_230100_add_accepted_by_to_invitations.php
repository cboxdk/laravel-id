<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('invitations', function (Blueprint $table): void {
            $table->string('accepted_by', 64)->nullable();
            $table->string('app_client_id')->nullable()->index();
        });
    }

    public function down(): void
    {
        Schema::table('invitations', function (Blueprint $table): void {
            $table->dropIndex(['app_client_id']);
        });

        Schema::table('invitations', function (Blueprint $table): void {
            $table->dropColumn(['accepted_by', 'app_client_id']);
        });
    }
};
