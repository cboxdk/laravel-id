<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Roles held EVERYWHERE in an environment, not inside one organization.
 *
 * `role_assignments.organization_id` is NOT NULL, so until now there was no way to say
 * "this person holds this role" without naming a tenant. That left three ordinary things
 * unrepresentable: a support agent of the product who must act across every customer, a
 * person who has not joined an organization yet, and any service provider that has no
 * tenancy of its own and therefore no organization to hang a grant on.
 *
 * A SEPARATE TABLE RATHER THAN A NULLABLE COLUMN, for two reasons.
 *
 * The first is that `unique(organization_id, user_id, role_id)` stops meaning anything
 * once the first column may be NULL: Postgres and MySQL both treat NULL as distinct in a
 * unique index, so the same environment-wide grant could be written twice and
 * `firstOrCreate` would never match it. The portable fixes are all worse than this —
 * MySQL has no partial indexes, and a sentinel value or a generated key is a second
 * encoding of the same fact.
 *
 * The second is that they are different statements. "Holds Editor in Acme" and "holds
 * Support everywhere" are not one fact with a field left blank; they are revoked
 * differently, reviewed differently, and one of them is a far larger thing to grant. A
 * column that is usually filled in hides that. And this migration only adds — it does not
 * touch a row of the table every existing grant lives in.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('environment_role_assignments', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('user_id', 26);
            $table->string('role_id', 26);
            $table->string('source')->default('manual');
            $table->string('source_ref')->nullable();
            $table->timestamps();

            // Every column is NOT NULL, so this means the same thing on every engine —
            // which is the whole argument for the shape.
            //
            // NAMED, because the generated name is 66 characters and MySQL's identifier
            // limit is 64. IndexPortabilityTest catches that before it reaches an engine
            // this repo's sqlite-only development would never have run against.
            $table->unique(['environment_id', 'user_id', 'role_id'], 'env_role_assignments_unique');
            $table->index(['user_id', 'environment_id'], 'env_role_assignments_user_idx');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('environment_role_assignments');
    }
};
