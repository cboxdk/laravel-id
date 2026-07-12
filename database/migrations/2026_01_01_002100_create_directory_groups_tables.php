<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('directory_groups', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('directory_id')->index();
            $table->string('external_id')->nullable();
            $table->string('display_name');
            $table->timestamps();

            $table->unique(['directory_id', 'display_name']);
        });

        Schema::create('directory_group_members', function (Blueprint $table): void {
            // Auto-increment pivot key so belongsToMany sync() doesn't need to
            // supply an id.
            $table->id();
            $table->ulid('group_id')->index();
            $table->ulid('directory_user_id')->index();
            $table->timestamps();

            $table->unique(['group_id', 'directory_user_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('directory_group_members');
        Schema::dropIfExists('directory_groups');
    }
};
