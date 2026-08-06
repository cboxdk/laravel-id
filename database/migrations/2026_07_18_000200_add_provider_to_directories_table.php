<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Directory sync gains API-PULL providers alongside the existing SCIM-push path.
 * A directory now carries a `provider` (scim = the customer's IdP pushes to us;
 * google_workspace / microsoft_entra = we pull from their API on a schedule) and,
 * for pull providers, sealed `credentials` (a service-account key / client secret)
 * plus last-sync bookkeeping. SCIM directories keep provider='scim' and never use
 * credentials — they authenticate with the bearer token as before. A pull directory
 * has no inbound token, so it's stored with a random unused hash (the column stays
 * unique + non-null; a random value is never matched by a presented token).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('directories', function (Blueprint $table): void {
            $table->string('provider')->default('scim')->after('name');
            // Sealed (Crypto SecretBox) provider credentials — only ever set for
            // pull providers. bearer_token_hash stays the auth for scim.
            $table->text('credentials')->nullable()->after('bearer_token_hash');
            $table->timestamp('last_synced_at')->nullable();
            $table->text('last_sync_error')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('directories', function (Blueprint $table): void {
            $table->dropColumn(['provider', 'credentials', 'last_synced_at', 'last_sync_error']);
        });
    }
};
