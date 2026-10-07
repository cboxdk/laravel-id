<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * When a client last had an access token minted — the fact pruning needs.
 *
 * Self-registered clients accumulate: an MCP client registers once per install, and most
 * installs are tried and abandoned. Telling an abandoned registration from a live one
 * cannot be read off the token tables, because those are themselves pruned days after the
 * tokens expire; a client used last week and one never used look the same there. So the
 * issuer stamps the client, at most once an hour, and `cbox-id:prune` can sweep
 * self-registered clients nobody has used in N days.
 *
 * Indexed because that sweep filters on it across every environment.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasTable('oauth_clients') || Schema::hasColumn('oauth_clients', 'last_used_at')) {
            return;
        }

        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->timestamp('last_used_at')->nullable()->index();
        });
    }

    public function down(): void
    {
        if (! Schema::hasTable('oauth_clients') || ! Schema::hasColumn('oauth_clients', 'last_used_at')) {
            return;
        }

        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->dropIndex(['last_used_at']);
        });

        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->dropColumn('last_used_at');
        });
    }
};
