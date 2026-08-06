<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Audit read model: the DSR / "everything done to (or by) a subject" exports
        // filter on target_type/target_id and actor_id, ordered by sequence
        // (see DatabaseAuditReader::query). The existing
        // (environment_id, organization_id, sequence) index only serves the org feed,
        // so those exports scanned the environment's audit partition.
        Schema::table('audit_logs', function (Blueprint $table): void {
            $table->index(
                ['environment_id', 'organization_id', 'target_type', 'target_id', 'sequence'],
                'audit_logs_env_org_target_seq_index',
            );
            $table->index(
                ['environment_id', 'actor_id', 'sequence'],
                'audit_logs_env_actor_seq_index',
            );
        });
    }

    public function down(): void
    {
        Schema::table('audit_logs', function (Blueprint $table): void {
            $table->dropIndex('audit_logs_env_org_target_seq_index');
            $table->dropIndex('audit_logs_env_actor_seq_index');
        });
    }
};
