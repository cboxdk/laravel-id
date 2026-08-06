<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Where an app publishes its authorization manifest for Cbox ID to PULL (the open,
 * zero-credential transport). A well-known URL like
 * `https://app.example.com/.well-known/cbox-authz`; null = the app pushes instead
 * (SDK / management API / manual). Fetched through the SSRF guard.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->string('manifest_url')->nullable()->after('scopes');
        });
    }

    public function down(): void
    {
        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->dropColumn('manifest_url');
        });
    }
};
