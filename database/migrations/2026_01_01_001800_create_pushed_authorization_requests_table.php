<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // RFC 9126: authorization request parameters pushed by a client, referenced
        // later by an opaque, single-use, short-lived request_uri.
        Schema::create('pushed_authorization_requests', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->string('request_uri')->unique();
            $table->string('client_id')->index();
            $table->json('params');
            $table->timestamp('expires_at');
            $table->timestamp('consumed_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('pushed_authorization_requests');
    }
};
