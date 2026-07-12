<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // One row per accepted SAML/OIDC assertion id — the unique constraint is
        // what makes replay of a captured, still-valid assertion impossible.
        Schema::create('consumed_assertions', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->string('assertion_id')->unique();
            $table->timestamp('expires_at')->index();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('consumed_assertions');
    }
};
