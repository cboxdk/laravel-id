<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Database\JsonDefault;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // An environment is the HARD isolation boundary: its own user pool,
        // signing keys, issuer and organization tree. The `slug` resolves the
        // environment from the request host/subdomain.
        Schema::create('environments', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('name');
            $table->string('slug')->unique();
            $table->string('domain')->nullable()->unique();
            $table->string('status')->default('active');
            // The single-tenant / host-less fallback plane. Kept in the database
            // (not an env var) so a horizontally-scaled, stateless deployment —
            // k8s with no writable .env — resolves the same default across every
            // replica. At most one row is true; enforced by Environment::makeDefault().
            $table->boolean('is_default')->default(false)->index();

            // The PRODUCT this environment is a stage of. Null for the platform root,
            // which is a stage of nothing — it is where the platform's own people and
            // its customers' organizations live.
            //
            // No foreign key, and `projects` is created after this table so there could
            // not be one declared here anyway. That ordering is a symptom rather than
            // the reason: an environment is the tenancy boundary itself, and the
            // platform plane does not take referential locks across it. A project id
            // that resolves to nothing reads as "owned by nobody", which is the safe
            // answer and the one every reader already handles.
            $table->string('project_id', 26)->nullable()->index();
            $table->json('settings')->default(JsonDefault::emptyObject());
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('environments');
    }
};
