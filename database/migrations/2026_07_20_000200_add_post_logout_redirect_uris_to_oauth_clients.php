<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The redirect URIs an RP may send the user-agent to AFTER an RP-initiated logout
 * (OpenID Connect RP-Initiated Logout 1.0 §2). The `end_session_endpoint` only
 * honors a `post_logout_redirect_uri` that exactly matches one registered here —
 * the allow-list that stops the logout endpoint becoming an open redirector.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->json('post_logout_redirect_uris')->nullable()->after('redirect_uris');
        });
    }

    public function down(): void
    {
        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->dropColumn('post_logout_redirect_uris');
        });
    }
};
