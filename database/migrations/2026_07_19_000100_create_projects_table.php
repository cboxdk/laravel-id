<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Projects — a single IdP product WITHIN an account, sitting between the account
 * (the login/identity umbrella) and its environments (the product's prod/staging/
 * dev stages). This is the Clerk "Application" / Auth0 "Tenant" layer: one login
 * (account) can own several independently-billed IdP products (projects), each with
 * its own environments.
 *
 * The plan/billing anchor lives HERE, not on the account: `environment_limit` is the
 * project's plan allowance, and a future subscription attaches to the project — so
 * "Product 1" and "Product 2" under the same account can be billed separately. The
 * account keeps only its members and payment methods.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('projects', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->foreignUlid('account_id')->constrained('accounts')->cascadeOnDelete();
            $table->string('name');
            // Human-friendly handle, unique within the owning account.
            $table->string('slug');
            $table->string('status')->default('active');
            // The plan's environment allowance for THIS project (moved off the
            // account). Default 2 = one production + one staging out of the box.
            $table->unsignedSmallInteger('environment_limit')->default(2);
            $table->json('settings')->default('{}');
            $table->timestamps();

            $table->unique(['account_id', 'slug']);
            $table->index('account_id');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('projects');
    }
};
