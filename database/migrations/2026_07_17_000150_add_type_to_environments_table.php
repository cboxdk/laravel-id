<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * An environment is either 'production' or 'sandbox' (a development/test realm).
 * Sandbox is a behavioural mode on the SAME infrastructure — not a separate
 * container — mirroring Stripe test mode, WorkOS staging, and Clerk development
 * instances: relaxed rules (e.g. localhost redirect URIs), no real outbound email,
 * and a clear "not production" banner. Defaults to production so an environment is
 * never silently treated as a test realm.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('environments', function (Blueprint $table): void {
            $table->string('type')->default('production')->after('slug');
        });
    }

    public function down(): void
    {
        Schema::table('environments', function (Blueprint $table): void {
            $table->dropColumn('type');
        });
    }
};
