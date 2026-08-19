<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Enums\TokenEndpointAuthMethod;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Records how a client authenticates, instead of guessing it back from the row's shape.
 *
 * `token_endpoint_auth_method` is a REGISTERED CHOICE (RFC 7591 §2) and it was never
 * stored: readback inferred it as public → `none`, has-JWKS → `private_key_jwt`, else
 * `client_secret_basic`. That is right about what a client CAN do and wrong about what it
 * asked for — the two shared-secret methods are indistinguishable from the row, so a
 * client that registered `client_secret_post` was told, in its own management document,
 * that it authenticates with Basic.
 *
 * The backfill writes exactly what the old inference would have answered, so every
 * existing client keeps the behaviour it has today and only NEW registrations can record
 * something the inference could not represent.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasColumn('oauth_clients', 'token_endpoint_auth_method')) {
            return;
        }

        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->string('token_endpoint_auth_method', 32)->nullable()->after('type');
        });

        // The old inference, written down once. Nullable and backfilled rather than
        // defaulted, so a row that somehow escapes this keeps reading as "unknown" and
        // falls back to the same inference rather than silently claiming Basic.
        DB::table('oauth_clients')
            ->where('type', ClientType::Public->value)
            ->update(['token_endpoint_auth_method' => TokenEndpointAuthMethod::None->value]);

        DB::table('oauth_clients')
            ->where('type', '!=', ClientType::Public->value)
            ->whereNotNull('jwks')
            ->update(['token_endpoint_auth_method' => TokenEndpointAuthMethod::PrivateKeyJwt->value]);

        DB::table('oauth_clients')
            ->where('type', '!=', ClientType::Public->value)
            ->whereNull('jwks')
            ->update(['token_endpoint_auth_method' => TokenEndpointAuthMethod::ClientSecretBasic->value]);
    }

    public function down(): void
    {
        if (! Schema::hasColumn('oauth_clients', 'token_endpoint_auth_method')) {
            return;
        }

        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->dropColumn('token_endpoint_auth_method');
        });
    }
};
