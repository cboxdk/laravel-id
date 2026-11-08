<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * The RFC 8707 resource a backchannel request named, so the token its poll yields is
 * bound to that audience. Additive and nullable: requests filed before it, and any that
 * name no resource, carry none.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('ciba_requests', function (Blueprint $table): void {
            $table->string('resource', 255)->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('ciba_requests', function (Blueprint $table): void {
            $table->dropColumn('resource');
        });
    }
};
