<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Database\JsonDefault;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('organizations', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('name');
            $table->string('slug');
            $table->string('parent_id', 26)->nullable()->index();
            $table->string('type')->default('customer');
            $table->string('status')->default('active');
            $table->json('settings')->default(JsonDefault::emptyObject());
            $table->timestamps();

            // Slugs are unique per environment, mirroring the users table's
            // (environment_id, email): the same slug may exist in two environments.
            $table->unique(['environment_id', 'slug']);
        });

        Schema::create('organization_closure', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('ancestor_id', 26);
            $table->string('descendant_id', 26);
            $table->unsignedInteger('depth');

            $table->unique(['ancestor_id', 'descendant_id']);
            $table->index('descendant_id');
        });

        Schema::create('memberships', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('organization_id', 26)->index();
            $table->string('user_id', 26);
            $table->string('role');
            $table->string('status')->default('active');

            // Whether this membership reaches every environment its organization owns, or
            // only the ones granted below. TRUE is the default and has to be: false means
            // "restricted to the empty set", so a member created without an explicit grant
            // would reach nothing. The restriction is what an administrator opts into.
            $table->boolean('all_environments')->default(true);

            $table->string('invited_by', 26)->nullable();
            $table->timestamps();

            $table->unique(['organization_id', 'user_id']);
        });

        // The environments a RESTRICTED membership may reach. Meaningless while
        // `all_environments` is true — the grants are the restriction, not the access —
        // and `setEnvironmentAccess()` detaches them when the restriction is lifted, so
        // the two halves can never disagree.
        Schema::create('membership_environments', function (Blueprint $table): void {
            $table->string('membership_id', 26);
            $table->string('environment_id', 26);

            // The primary key IS the pair: a grant either exists or it does not, and a
            // surrogate id would let the same grant be written twice with nothing
            // objecting. Its leftmost prefix is also the `membership_id` lookup, which is
            // the only direction anything reads.
            //
            // 52 bytes of key — inside MySQL's 3072-byte limit even on the
            // 4-bytes-per-character utf8mb4 worst case.
            $table->primary(['membership_id', 'environment_id']);

            $table->foreign('membership_id')->references('id')->on('memberships')->cascadeOnDelete();

            // No foreign key to `environments`, deliberately. A membership and its grants
            // are one object and go together; an environment is on the other side of the
            // tenancy boundary. A grant naming an environment that has since been deleted
            // reads as no access, which is the safe direction.
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('membership_environments');
        Schema::dropIfExists('memberships');
        Schema::dropIfExists('organization_closure');
        Schema::dropIfExists('organizations');
    }
};
