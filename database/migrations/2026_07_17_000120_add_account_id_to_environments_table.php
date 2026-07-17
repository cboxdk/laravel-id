<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Every environment belongs to an account — its owner. The column is nullable
 * because the platform-root/default environment (Cbox's own, or a self-hosted
 * single-tenant install) is platform-owned, not a customer account: null means
 * "owned by the platform, managed by operators". A customer's self-serve
 * environment always carries its owning account_id.
 *
 * restrictOnDelete, NOT nullOnDelete: null account_id is the sentinel for a
 * platform-owned environment, so nulling a customer's environments on account
 * delete would silently convert live customer IdPs into platform-owned ones while
 * they keep serving. Instead the FK BLOCKS deleting an account that still owns
 * environments — teardown must explicitly remove the environments first, so an IdP
 * realm can never be orphaned as a side effect.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('environments', function (Blueprint $table): void {
            $table->foreignUlid('account_id')->nullable()->after('id')
                ->constrained('accounts')->restrictOnDelete();

            $table->index('account_id');
        });
    }

    public function down(): void
    {
        Schema::table('environments', function (Blueprint $table): void {
            $table->dropConstrainedForeignId('account_id');
        });
    }
};
