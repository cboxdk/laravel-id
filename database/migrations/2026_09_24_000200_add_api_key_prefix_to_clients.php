<?php

declare(strict_types=1);

use Cbox\Id\Organization\ValueObjects\ApiKeyPrefix;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The prefix an app's customer API keys carry (`ctx_live` → `ctx_live_…`).
 *
 * Declaring one is how an app opts in to customer API keys: a client with no prefix
 * issues none. The format is {@see ApiKeyPrefix}'s to police; the column only holds it.
 *
 * Unique per environment, so a key found in a log or a secret scan names exactly one app.
 * Nullable columns in a composite unique index admit any number of NULL rows on all four
 * engines, so every client that has not opted in coexists.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasTable('oauth_clients') || Schema::hasColumn('oauth_clients', 'api_key_prefix')) {
            return;
        }

        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->string('api_key_prefix', 32)->nullable();
            $table->unique(['environment_id', 'api_key_prefix'], 'oauth_clients_env_api_key_prefix_unique');
        });
    }

    public function down(): void
    {
        if (! Schema::hasTable('oauth_clients') || ! Schema::hasColumn('oauth_clients', 'api_key_prefix')) {
            return;
        }

        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->dropUnique('oauth_clients_env_api_key_prefix_unique');
        });

        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->dropColumn('api_key_prefix');
        });
    }
};
