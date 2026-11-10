<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * RFC 9396 (Rich Authorization Requests) §10: the `authorization_details` types a client
 * may ask for. Null (every existing client) means none: a client that never registered a
 * type cannot put authorization details on a token. Additive and nullable.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('oauth_clients') && ! Schema::hasColumn('oauth_clients', 'authorization_details_types')) {
            Schema::table('oauth_clients', function (Blueprint $table): void {
                $table->json('authorization_details_types')->nullable();
            });
        }
    }

    public function down(): void
    {
        if (Schema::hasTable('oauth_clients') && Schema::hasColumn('oauth_clients', 'authorization_details_types')) {
            Schema::table('oauth_clients', function (Blueprint $table): void {
                $table->dropColumn('authorization_details_types');
            });
        }
    }
};
