<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Platform operators — the identity that sits ABOVE every environment (the
 * WorkOS "team member" / developer account). Unlike users, an operator is not
 * environment-owned: it has no environment_id and its email is globally unique,
 * because it can assume any environment's console. This table is the counterpart
 * to `environments`: environments are the boundary, operators are who stand above
 * it.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('platform_operators', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->string('email')->unique();
            $table->string('name')->nullable();
            $table->string('password');
            $table->string('status')->default('active');
            $table->timestamp('last_login_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('platform_operators');
    }
};
