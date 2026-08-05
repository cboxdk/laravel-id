<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Database\JsonDefault;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Projects — a single IdP product an ORGANIZATION owns, sitting between the
 * organization (who the customer is, and who may act for them) and its environments
 * (that product's prod/staging/dev stages).
 *
 * One organization can own several independently-billed products, each with its own
 * environments. The plan anchor lives HERE: `environment_limit` is the project's
 * allowance, and a subscription attaches to the project — so two products belonging to
 * the same customer are billed separately.
 *
 * THERE IS NO ACCOUNT ABOVE THIS. There was: a separate `accounts` table, with its own
 * members, its own roles and its own credential store, which an organization then
 * shadowed one-to-one in the platform-root environment. Two rows for one customer and
 * two answers to "who may act for them" — every seam between them was a bug, and the
 * last of them (a per-member environment grant that lived on one side and was read from
 * the other) is why the pair is gone rather than reconciled. The customer IS an
 * organization; a member of it IS a membership.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('projects', function (Blueprint $table): void {
            $table->string('id', 26)->primary();

            // The ORGANIZATION that owns this product. No foreign key: `organizations` is
            // environment-owned and the platform plane does not take referential locks
            // across the tenancy boundary — the unique index below is the guard that
            // matters, and it costs no lock on `organizations` when this runs.
            $table->string('organization_id', 26);

            $table->string('name');
            // Human-friendly handle, unique within the owning organization.
            $table->string('slug');
            $table->string('status')->default('active');
            // The plan's environment allowance for THIS project (moved off the
            // account). Default 2 = one production + one staging out of the box.
            $table->unsignedSmallInteger('environment_limit')->default(2);
            $table->json('settings')->default(JsonDefault::emptyObject());
            $table->timestamps();

            // A project handle is unique within its owner: two organizations may each
            // have a "default", one organization may not have two. The leftmost prefix is
            // also the `organization_id` lookup, so no separate index is added.
            $table->unique(['organization_id', 'slug']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('projects');
    }
};
