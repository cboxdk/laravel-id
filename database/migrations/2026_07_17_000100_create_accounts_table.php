<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Accounts — the customer's workspace, the plane that OWNS environments (the
 * WorkOS "Workspace" / Auth0 "Account" / Clerk "Workspace" / Frontegg "Portal
 * account"). This is where billing/plan lives and where an account member signs
 * in at the platform root and switches between the account's environments.
 *
 * An account is NOT environment-owned — it sits ABOVE environments, the same way
 * operators do. Its `environment_limit` encodes the plan's environment allowance
 * ("a plan with 2 environments"), the one dial Frontegg gates by tier.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('accounts', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->string('name');
            $table->string('status')->default('active');
            // The plan's environment allowance. Default 2 mirrors the industry
            // norm of one production + one staging out of the box.
            $table->unsignedSmallInteger('environment_limit')->default(2);
            $table->json('settings')->default('{}');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('accounts');
    }
};
