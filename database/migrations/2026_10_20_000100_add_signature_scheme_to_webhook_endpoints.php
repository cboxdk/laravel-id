<?php

declare(strict_types=1);

use Cbox\Id\Webhooks\Enums\SignatureScheme;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * How each webhook endpoint's deliveries are signed ({@see SignatureScheme}).
 *
 * NOT NULL with a default of `cbox`, so every endpoint that exists when this runs — and
 * every row a host inserts without naming the column — stays on the scheme it has always
 * been delivered with, byte for byte. Only an explicit choice moves an endpoint to
 * Standard Webhooks. A plain short string (no enum type, no check constraint) so the
 * column reads the same on SQLite, MySQL, MariaDB and PostgreSQL and a later scheme is a
 * code change, not a schema one.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('webhook_endpoints', function (Blueprint $table): void {
            $table->string('signature_scheme', 32)->default('cbox');
        });
    }

    public function down(): void
    {
        Schema::table('webhook_endpoints', function (Blueprint $table): void {
            $table->dropColumn('signature_scheme');
        });
    }
};
