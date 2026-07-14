<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // An environment is the HARD isolation boundary: its own user pool,
        // signing keys, issuer and organization tree. The `slug` resolves the
        // environment from the request host/subdomain.
        Schema::create('environments', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->string('name');
            $table->string('slug')->unique();
            $table->string('domain')->nullable()->unique();
            $table->string('status')->default('active');
            // The single-tenant / host-less fallback plane. Kept in the database
            // (not an env var) so a horizontally-scaled, stateless deployment —
            // k8s with no writable .env — resolves the same default across every
            // replica. At most one row is true; enforced by Environment::makeDefault().
            $table->boolean('is_default')->default(false)->index();
            $table->json('settings')->default('{}');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('environments');
    }
};
