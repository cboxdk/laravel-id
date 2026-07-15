<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('otp_challenges', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->string('purpose');
            $table->string('channel');
            $table->string('recipient');
            // Only the KEYED hash of the code is ever stored — never the plaintext.
            $table->string('code_hash');
            $table->timestamp('expires_at');
            $table->unsignedTinyInteger('attempts')->default(0);
            $table->unsignedTinyInteger('max_attempts');
            $table->timestamp('consumed_at')->nullable();
            $table->timestamps();

            // The verifyLatest() lookup: newest live challenge for a recipient+purpose
            // within an environment.
            $table->index(['environment_id', 'recipient', 'purpose']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('otp_challenges');
    }
};
