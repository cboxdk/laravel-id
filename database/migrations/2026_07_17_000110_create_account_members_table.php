<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Account members — the login identities that administer an account and its
 * environments from the platform root (the buyer/developer plane, distinct from
 * end-users who authenticate INTO an environment and never see this console).
 *
 * Like operators, a member is NOT environment-owned: it authenticates once at the
 * root and can then step into any environment the account owns. Its email is
 * globally unique so "I forgot which subdomain / I have several" resolves to a
 * single root login. A member belongs to exactly one account (multi-account
 * membership is a later refinement, deliberately not modelled yet).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('account_members', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->foreignUlid('account_id')->constrained('accounts')->cascadeOnDelete();
            $table->string('email')->unique();
            $table->string('name')->nullable();
            $table->string('password');
            $table->string('status')->default('active');
            $table->timestamp('last_login_at')->nullable();
            $table->timestamps();

            $table->index('account_id');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('account_members');
    }
};
