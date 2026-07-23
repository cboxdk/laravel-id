<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Group metadata only. Membership is deliberately NOT a column here —
        // it lives as relationship tuples (user_group:<id> #member @user:<id>),
        // so group-inherited access resolves through the same userset expansion
        // as every other grant and there is exactly one membership store.
        Schema::create('user_groups', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->ulid('organization_id')->index();
            $table->string('name');
            $table->timestamps();

            $table->unique(['organization_id', 'name']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('user_groups');
    }
};
