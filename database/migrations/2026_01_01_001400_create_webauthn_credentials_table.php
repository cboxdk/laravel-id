<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('webauthn_credentials', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('user_id')->index();
            $table->string('credential_id')->unique();
            $table->text('public_key');
            $table->unsignedBigInteger('sign_count')->default(0);
            $table->json('transports')->default('[]');
            $table->string('name')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('webauthn_credentials');
    }
};
