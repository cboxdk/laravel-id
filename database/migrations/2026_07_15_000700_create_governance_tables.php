<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Access-certification campaigns: a point-in-time review of an org's access.
        Schema::create('governance_campaigns', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->ulid('organization_id')->index();
            $table->string('name');
            $table->string('status')->default('open'); // open | closed
            $table->string('pending_policy')->default('revoke'); // revoke | certify
            $table->timestamp('due_at')->nullable();
            $table->string('created_by')->nullable();
            $table->timestamp('closed_at')->nullable();
            $table->timestamps();

            // The scheduler scans for open, past-due campaigns across environments.
            $table->index(['status', 'due_at']);
        });

        // One reviewable access grant within a campaign (a role assignment or a
        // membership), awaiting a certify/revoke decision.
        Schema::create('governance_certification_items', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->ulid('campaign_id')->index();
            $table->string('access_type'); // role | membership
            $table->string('subject_id');
            $table->string('access_ref');  // role_id, or the membership role
            $table->ulid('organization_id');
            $table->string('source')->nullable();
            $table->string('reviewer_id')->nullable();
            $table->string('decision')->default('pending'); // pending | certified | revoked
            $table->string('decided_by')->nullable();
            $table->timestamp('decided_at')->nullable();
            $table->string('note')->nullable();
            $table->boolean('applied')->default(false);
            $table->string('application_note')->nullable();
            $table->timestamps();
        });

        // Segregation-of-Duties policies: a mutually-exclusive set of roles.
        Schema::create('governance_sod_policies', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->ulid('organization_id')->nullable()->index(); // null = env-wide
            $table->string('name');
            $table->string('description')->nullable();
            $table->boolean('active')->default(true);
            $table->json('role_ids')->default('[]');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('governance_sod_policies');
        Schema::dropIfExists('governance_certification_items');
        Schema::dropIfExists('governance_campaigns');
    }
};
