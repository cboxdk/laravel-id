<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The resource indicator the user actually authorized (RFC 8707 §2).
 *
 * `resource` was read at the token endpoint, validated as an absolute URI, and stamped
 * verbatim into the access token's `aud` — with nothing anywhere recording what the
 * authorization had been FOR. So a client holding a valid code could ask for any
 * audience it liked at redemption and receive a token asserting it.
 *
 * That is a confused deputy against any resource server that trusts this issuer and
 * checks `aud`, which is exactly the check RFC 9068 tells a resource server to make and
 * the property the MCP authorization model is built on: the token says our issuer minted
 * it for them, and the person it names never agreed to that.
 *
 * §2.2 requires the token request's resource to be the same as, or a subset of, what was
 * authorized. This column is what makes "what was authorized" a fact rather than an
 * assumption.
 *
 * Nullable, and null keeps the previous behaviour: a code issued before this column
 * existed, or by an authorization that named no resource, is not retroactively bound to
 * something it never had.
 */
return new class extends Migration
{
    public function up(): void
    {
        // Both guards. A suite that loads a subset of migration paths reaches this file
        // without the table the OAuth create migration makes, and `hasColumn` on a
        // missing table answers false — so the ALTER ran and failed.
        //
        // The guard also hides a typo: with the wrong table name this migration skips
        // silently and the column simply never appears, which surfaces later as a failing
        // INSERT. It did exactly that once. The name below is the real one.
        if (! Schema::hasTable('oauth_authorization_codes') || Schema::hasColumn('oauth_authorization_codes', 'resource')) {
            return;
        }

        Schema::table('oauth_authorization_codes', function (Blueprint $table): void {
            // 512 to match the resource column already on access tokens. Not indexed:
            // it is only ever read through a code that has been located by its hash.
            $table->string('resource', 512)->nullable()->after('scopes');
        });
    }

    public function down(): void
    {
        if (! Schema::hasTable('oauth_authorization_codes')) {
            return;
        }

        Schema::table('oauth_authorization_codes', function (Blueprint $table): void {
            $table->dropColumn('resource');
        });
    }
};
