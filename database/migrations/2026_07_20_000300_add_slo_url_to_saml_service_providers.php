<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The SP's SingleLogoutService (SLO) Location — where the IdP sends a signed
 * `LogoutResponse` after processing that SP's `LogoutRequest` (SAML 2.0 Single
 * Logout, HTTP-Redirect binding). Null = the SP did not register an SLO endpoint,
 * so the IdP tears down the local session but has nowhere to return a response.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('saml_service_providers', function (Blueprint $table): void {
            $table->text('slo_url')->nullable()->after('acs_url');
        });
    }

    public function down(): void
    {
        Schema::table('saml_service_providers', function (Blueprint $table): void {
            $table->dropColumn('slo_url');
        });
    }
};
