<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // RFC 8628 device grant: the device_code is stored as a SHA-256 hash (the
        // raw value is the client's polling secret); the user_code is what a human
        // types at the verification URI.
        Schema::create('device_codes', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->string('device_code_hash')->unique();
            $table->string('user_code')->unique();
            $table->string('client_id')->index();
            $table->json('scopes')->default('[]');
            $table->string('status')->default('pending'); // pending | approved | denied
            $table->string('user_id')->nullable();
            $table->string('organization_id')->nullable();
            $table->unsignedInteger('interval')->default(5);
            $table->timestamp('last_polled_at')->nullable();
            $table->timestamp('expires_at');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('device_codes');
    }
};
