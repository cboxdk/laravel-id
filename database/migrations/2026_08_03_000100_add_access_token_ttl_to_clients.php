<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * How long this client's access tokens live, when the deployment default is wrong for it.
 *
 * The TTL was a single deployment-wide value, and that is the wrong shape as soon as one
 * issuer serves relying parties with different revocation stories.
 *
 * The case that forced it: a `kubectl` credential. Kubernetes validates a JWT offline —
 * it never calls back — so revoking a session stops the NEXT token and leaves the one
 * already on the laptop valid until it expires. The revocation window IS the TTL. Five
 * minutes is a real answer to "their laptop was stolen"; fifteen is a worse one, and a
 * browser session has no reason to pay five-minute refreshes for it.
 *
 * Nullable, and null means the deployment default — so no existing client changes.
 */
return new class extends Migration
{
    public function up(): void
    {
        // The table is `oauth_clients`. Named explicitly rather than guessed: the last
        // migration here targeted a name that did not exist, and the hasTable guard
        // turned that into a silent skip that surfaced as a failing INSERT much later.
        if (! Schema::hasTable('oauth_clients') || Schema::hasColumn('oauth_clients', 'access_token_ttl')) {
            return;
        }

        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->unsignedInteger('access_token_ttl')->nullable()->after('scopes');
        });
    }

    public function down(): void
    {
        if (! Schema::hasTable('oauth_clients')) {
            return;
        }

        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->dropColumn('access_token_ttl');
        });
    }
};
