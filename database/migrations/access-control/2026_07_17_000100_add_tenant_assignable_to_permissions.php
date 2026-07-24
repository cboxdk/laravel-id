<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * `tenant_assignable` marks whether a tenant admin may compose a declared permission
 * into their own custom roles. Default true (every existing permission stays
 * assignable); an app opts a privileged permission out via its manifest so it is
 * app-only — usable in the app's declared roles but hidden from the tenant picker.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('permissions', function (Blueprint $table): void {
            $table->boolean('tenant_assignable')->default(true)->after('description');
        });
    }

    public function down(): void
    {
        Schema::table('permissions', function (Blueprint $table): void {
            $table->dropColumn('tenant_assignable');
        });
    }
};
