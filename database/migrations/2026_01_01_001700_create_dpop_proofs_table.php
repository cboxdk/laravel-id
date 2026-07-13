<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Seen DPoP proof ids (RFC 9449 §11.1). The unique jti is the replay guard;
        // rows expire with the proof's freshness window and can be pruned.
        Schema::create('dpop_proofs', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->string('jti')->unique();
            $table->timestamp('expires_at');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('dpop_proofs');
    }
};
