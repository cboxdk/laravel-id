<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('verified_domains', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->ulid('organization_id')->index();
            $table->string('domain');
            // The org publishes this token in a DNS TXT record to prove control.
            $table->string('verification_token');
            $table->timestamp('verified_at')->nullable();
            // The OPTIONAL gate: when true, users whose email matches this
            // verified domain are captured into the org's auth policy (SSO) — not
            // just offered home-realm routing. Off by default; enforced by the host.
            $table->boolean('capture')->default(false);
            $table->timestamps();

            // A domain belongs to at most one organization per environment.
            $table->unique(['environment_id', 'domain']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('verified_domains');
    }
};
