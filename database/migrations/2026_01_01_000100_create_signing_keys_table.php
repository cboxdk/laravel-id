<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('signing_keys', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->string('kid')->unique();
            $table->string('alg');
            $table->text('public_key');
            $table->text('private_key_encrypted');
            $table->string('status')->index();
            $table->timestamp('activated_at')->nullable();
            $table->timestamp('retired_at')->nullable();
            $table->timestamps();

            $table->index(['alg', 'status']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('signing_keys');
    }
};
