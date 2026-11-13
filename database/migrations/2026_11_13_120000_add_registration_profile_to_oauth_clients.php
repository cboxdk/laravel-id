<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * The registration profile an RFC 7591 client registered under: `mcp` (open registration
 * held to the MCP profile) or `general` (`open` or `protected`). An RFC 7592 update is
 * validated against it, never against whatever the server's mode is today. Null for an
 * operator-created client, and for a self-registered client written before this column:
 * {@see \Cbox\Id\OAuthServer\Models\Client::registrationProfile()} reads such a row from
 * its shape (no shared secret = held to the MCP profile). Additive and nullable.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasTable('oauth_clients') || Schema::hasColumn('oauth_clients', 'registration_profile')) {
            return;
        }

        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->string('registration_profile', 16)->nullable();
        });
    }

    public function down(): void
    {
        if (Schema::hasTable('oauth_clients') && Schema::hasColumn('oauth_clients', 'registration_profile')) {
            Schema::table('oauth_clients', function (Blueprint $table): void {
                $table->dropColumn('registration_profile');
            });
        }
    }
};
