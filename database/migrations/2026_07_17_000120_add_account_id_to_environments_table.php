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
 * nullOnDelete rather than cascade: deleting an account is a heavyweight,
 * audited operation that must tear down its environments deliberately — it must
 * never silently drop a whole IdP realm as a side effect of a foreign key.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('environments', function (Blueprint $table): void {
            $table->foreignUlid('account_id')->nullable()->after('id')
                ->constrained('accounts')->nullOnDelete();

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
