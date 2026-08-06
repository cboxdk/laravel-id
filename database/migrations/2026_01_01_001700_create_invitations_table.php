<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('invitations', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('organization_id', 26)->index();
            $table->string('email')->index();
            $table->string('role');
            $table->string('token_hash')->unique();
            $table->string('status')->default('pending');
            $table->string('invited_by', 26)->nullable();
            $table->timestamp('expires_at');
            $table->timestamp('accepted_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('invitations');
    }
};
