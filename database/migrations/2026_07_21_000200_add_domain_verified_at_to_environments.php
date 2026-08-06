<?php

declare(strict_types=1);

use Cbox\Id\Organization\EnvironmentDomainService;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * When a custom domain became the environment's ISSUER identity (OIDC `iss` / SAML
 * entityID), the `domain` column turned security-critical — yet it can be written by
 * routing/branding paths that never prove DNS control. This adds an explicit
 * verification timestamp: only {@see EnvironmentDomainService}
 * (DNS-TXT proof) sets it, and the issuer resolver trusts a custom domain ONLY when
 * it is set. An unverified domain still routes/brands but can never assert an issuer.
 *
 * Existing non-null domains are backfilled as verified: they were written either by
 * the DNS-verified promotion path or by trusted operator provisioning — both of which
 * now stamp domain_verified_at going forward, so the invariant "domain set ⇒ verified"
 * holds for every writer.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('environments', function (Blueprint $table): void {
            $table->timestamp('domain_verified_at')->nullable()->after('domain');
        });

        DB::table('environments')->whereNotNull('domain')->update(['domain_verified_at' => now()]);
    }

    public function down(): void
    {
        Schema::table('environments', function (Blueprint $table): void {
            $table->dropColumn('domain_verified_at');
        });
    }
};
