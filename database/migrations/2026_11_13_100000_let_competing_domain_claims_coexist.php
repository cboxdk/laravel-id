<?php

declare(strict_types=1);

use Cbox\Id\Federation\DatabaseDomainVerification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Only a PROVEN domain belongs to one organization.
 *
 * `unique(environment_id, domain)` let exactly one row exist per domain, verified or not,
 * so the first organization to TYPE a domain owned it: the real owner was refused and never
 * got a DNS challenge to publish. Each organization now holds its own pending claim, and
 * {@see DatabaseDomainVerification} keeps the rule that matters — at
 * most one VERIFIED row per domain — where it stamps the verification.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('verified_domains', function (Blueprint $table): void {
            $table->index(['environment_id', 'domain']);
        });

        Schema::table('verified_domains', function (Blueprint $table): void {
            $table->dropUnique(['environment_id', 'domain']);
            $table->unique(['environment_id', 'organization_id', 'domain']);
        });
    }

    public function down(): void
    {
        Schema::table('verified_domains', function (Blueprint $table): void {
            $table->dropUnique(['environment_id', 'organization_id', 'domain']);
            $table->unique(['environment_id', 'domain']);
        });

        Schema::table('verified_domains', function (Blueprint $table): void {
            $table->dropIndex(['environment_id', 'domain']);
        });
    }
};
