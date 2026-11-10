<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * CIBA ping mode (CIBA Core §5, §10.2).
 *
 * On the client: the delivery mode it registered (null = poll, so no existing client
 * changes) and the https endpoint an operator registered for its notifications.
 *
 * On the request: the client's `client_notification_token` and its own `auth_req_id`,
 * both ENCRYPTED (the model casts them) and both only for a ping-mode request. The
 * notification needs them raw — the token is the bearer credential the client checks, and
 * the auth_req_id is what it is told about — while the lookup column stays a hash. Both
 * are cleared once the notification is delivered or the request is redeemed.
 *
 * Additive and nullable throughout.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('oauth_clients') && ! Schema::hasColumn('oauth_clients', 'backchannel_token_delivery_mode')) {
            Schema::table('oauth_clients', function (Blueprint $table): void {
                $table->string('backchannel_token_delivery_mode', 16)->nullable();
                $table->string('backchannel_client_notification_endpoint', 2048)->nullable();
            });
        }

        if (Schema::hasTable('ciba_requests') && ! Schema::hasColumn('ciba_requests', 'client_notification_token')) {
            Schema::table('ciba_requests', function (Blueprint $table): void {
                $table->text('client_notification_token')->nullable();
                $table->text('notification_auth_req_id')->nullable();
            });
        }
    }

    public function down(): void
    {
        if (Schema::hasTable('oauth_clients') && Schema::hasColumn('oauth_clients', 'backchannel_token_delivery_mode')) {
            Schema::table('oauth_clients', function (Blueprint $table): void {
                $table->dropColumn(['backchannel_token_delivery_mode', 'backchannel_client_notification_endpoint']);
            });
        }

        if (Schema::hasTable('ciba_requests') && Schema::hasColumn('ciba_requests', 'client_notification_token')) {
            Schema::table('ciba_requests', function (Blueprint $table): void {
                $table->dropColumn(['client_notification_token', 'notification_auth_req_id']);
            });
        }
    }
};
