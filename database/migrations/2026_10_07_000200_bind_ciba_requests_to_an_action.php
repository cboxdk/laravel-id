<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Contracts\ActionApprovals;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * A CIBA request can now ask a person to approve one ACTION rather than to sign an agent
 * in: "deploy-bot wants to rotate the secret of app 'Billing'".
 *
 * `action_digest` is the host's hash of exactly what is being approved (the action, its
 * target, its input), so an approval for one change can never be spent on another;
 * `purpose` is a short machine label (`action`). A request with an action digest is
 * consumed by the host and is NEVER redeemable for tokens at the token endpoint.
 * {@see ActionApprovals}
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('ciba_requests', function (Blueprint $table): void {
            $table->string('purpose', 32)->nullable();
            $table->string('action_digest', 64)->nullable();
            $table->timestamp('consumed_at')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('ciba_requests', function (Blueprint $table): void {
            $table->dropColumn(['purpose', 'action_digest', 'consumed_at']);
        });
    }
};
