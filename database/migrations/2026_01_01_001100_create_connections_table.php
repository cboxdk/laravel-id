<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('connections', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('organization_id')->index();
            $table->string('type');
            $table->string('name');
            $table->string('status')->default('draft');
            $table->text('config_encrypted');
            $table->json('mappings')->default('{}');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('connections');
    }
};
