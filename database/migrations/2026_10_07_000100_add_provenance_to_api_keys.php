<?php

declare(strict_types=1);

use Cbox\Id\Platform\ValueObjects\KeyProvenance;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Where a management key came from, so a key can mint keys and the chain stays answerable.
 *
 * A key minted in the console has a person behind it; a key minted by another key has a
 * PARENT, and revoking the parent must be able to find its children. `rotated_from_id`
 * links a successor to the key it replaces. `step_up_policy` is the host's: which actions
 * this key may only run with a person's approval. `scopes` on organization keys lets them
 * be narrowed below their role, as environment keys always could be.
 *
 * All nullable and additive: every existing key reads as "minted by an unknown person, no
 * parent, no policy", which is exactly what it was. {@see KeyProvenance}
 */
return new class extends Migration
{
    public function up(): void
    {
        foreach (['environment_api_keys', 'organization_api_keys'] as $table) {
            Schema::table($table, function (Blueprint $table): void {
                $table->string('description', 500)->nullable();
                $table->string('created_by_type', 32)->nullable();
                $table->string('created_by_id', 64)->nullable();
                $table->string('parent_key_id', 26)->nullable()->index();
                $table->string('rotated_from_id', 26)->nullable();
                $table->json('step_up_policy')->nullable();
            });
        }

        Schema::table('organization_api_keys', function (Blueprint $table): void {
            $table->json('scopes')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('organization_api_keys', function (Blueprint $table): void {
            $table->dropColumn('scopes');
        });

        foreach (['environment_api_keys', 'organization_api_keys'] as $table) {
            Schema::table($table, function (Blueprint $table): void {
                $table->dropIndex(['parent_key_id']);
                $table->dropColumn(['description', 'created_by_type', 'created_by_id', 'parent_key_id', 'rotated_from_id', 'step_up_policy']);
            });
        }
    }
};
