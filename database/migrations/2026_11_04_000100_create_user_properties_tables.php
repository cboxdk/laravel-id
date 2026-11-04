<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('user_property_namespaces', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 64)->index();
            $table->string('name', 64);
            $table->json('readers');
            $table->json('writers');
            $table->json('webhooks');
            $table->timestamps();
            $table->unique(['environment_id', 'name']);
        });
        Schema::create('user_property_documents', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 64)->index();
            $table->string('user_id', 64)->index();
            $table->string('namespace', 64);
            $table->json('data');
            $table->unsignedBigInteger('version');
            $table->timestamps();
            $table->unique(['environment_id', 'user_id', 'namespace'], 'user_properties_subject_namespace_unique');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('user_property_documents');
        Schema::dropIfExists('user_property_namespaces');
    }
};
