<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Customer API keys: a user API token BOUND TO ONE APP.
 *
 * A `cbid_pat_` token authenticates as its user within an organization and carries a
 * coarse verb. A customer API key is the same credential — same table, same hashing,
 * same tenancy, same revocation — plus the two facts an app needs to accept it as a key
 * for ITS API: the `client_id` it was issued for, and the subset of that app's
 * permissions it may exercise. A row with a `client_id` is a customer API key; a row
 * without one is a personal token, exactly as every existing row is.
 *
 * `scope` and `name` become nullable because a customer key carries permissions instead
 * of a verb and its name is optional. Every personal token keeps both — the issuing
 * service always writes them — so no existing row changes.
 *
 * `prefix` widens from 16 to 40: the listing fragment of a customer key is the app's own
 * prefix (up to 21 characters, `ctx_live`) plus the first characters of the random part.
 * Twelve characters of a key whose prefix alone can be twenty-one would identify nothing.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('user_api_tokens', function (Blueprint $table): void {
            // The public OAuth `client_id` (`cid_…`), NOT the client's ULID primary key:
            // it is the identifier roles and permissions are declared against, and the
            // one the app authenticates with. Full string width — a client id is not a
            // ULID (see 2026_08_26_000100_widen_the_legacy_login_client_id).
            $table->string('client_id')->nullable();
            $table->json('permissions')->nullable();

            // Named: the generated name is 63 characters and one column away from the
            // PostgreSQL identifier limit.
            $table->index(['client_id', 'organization_id', 'user_id'], 'user_api_tokens_client_org_user_index');
        });

        Schema::table('user_api_tokens', function (Blueprint $table): void {
            $table->string('scope')->nullable()->change();
            $table->string('name')->nullable()->change();
            $table->string('prefix', 40)->change();
        });
    }

    public function down(): void
    {
        // A customer API key has no verb and may have no name, so it cannot survive the
        // columns going back to NOT NULL. Rolling back the feature revokes its keys by
        // removing them; the personal tokens are untouched.
        DB::table('user_api_tokens')->whereNotNull('client_id')->delete();

        Schema::table('user_api_tokens', function (Blueprint $table): void {
            $table->dropIndex('user_api_tokens_client_org_user_index');
        });

        Schema::table('user_api_tokens', function (Blueprint $table): void {
            $table->dropColumn(['client_id', 'permissions']);
        });

        Schema::table('user_api_tokens', function (Blueprint $table): void {
            $table->string('scope')->nullable(false)->change();
            $table->string('name')->nullable(false)->change();
            $table->string('prefix', 16)->change();
        });
    }
};
