<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('oauth_service_accounts', function (Blueprint $table): void {
            // The predecessor this account was rotated from — links a successor
            // credential back to the one it supersedes during an overlap window.
            $table->string('rotated_from')->nullable()->after('client_id');
            $table->timestamp('retired_at')->nullable()->after('status');
        });
    }

    public function down(): void
    {
        Schema::table('oauth_service_accounts', function (Blueprint $table): void {
            $table->dropColumn(['rotated_from', 'retired_at']);
        });
    }
};
