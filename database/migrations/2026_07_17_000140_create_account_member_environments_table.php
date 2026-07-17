<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Per-environment access grants for scoped members (those with
 * all_environments = false). Only consulted for such members; owners/admins and
 * any member with all_environments = true reach every environment the account owns
 * without a row here.
 *
 * cascadeOnDelete on both sides: a grant is meaningless once either the member or
 * the environment is gone.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('account_member_environments', function (Blueprint $table): void {
            $table->foreignUlid('account_member_id')->constrained('account_members')->cascadeOnDelete();
            $table->foreignUlid('environment_id')->constrained('environments')->cascadeOnDelete();
            $table->timestamps();

            // A pure pivot: the (member, environment) pair is the key — no surrogate
            // id, so belongsToMany sync() inserts need nothing generated.
            $table->primary(['account_member_id', 'environment_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('account_member_environments');
    }
};
