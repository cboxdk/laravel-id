<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Which catalogue entry a connection came from, when it came from one.
 *
 * Before this, a connection was either SAML or OIDC and nothing recorded whether an
 * administrator had described it by hand or picked "GitHub" from a list. Two things
 * needed that distinction:
 *
 *  - A tenant may enable SEVERAL catalogue providers at once (Google and GitHub and
 *    Apple), while `forOrganization()` answers "the organization's enterprise sign-on
 *    connection" and must keep answering exactly that. Without a column the two kinds
 *    are indistinguishable and the first active row wins whichever it happens to be.
 *  - Rendering a sign-in button needs the provider's name and mark. Reading that from
 *    the sealed config would mean unsealing every connection on every login page.
 *
 * Nullable, because a hand-configured enterprise connection genuinely has no catalogue
 * entry — that is the honest value, not a placeholder. Existing rows become NULL, which
 * is what they are, so nothing about them changes.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('connections', function (Blueprint $table): void {
            // 64 rather than the default 255: catalogue keys are short slugs, and this
            // column joins an index with organization_id where every byte counts against
            // the 3072-byte limit (see IndexPortabilityTest).
            $table->string('provider', 64)->nullable()->after('type');

            // The login page's query: this organization's active catalogue providers.
            $table->index(['organization_id', 'provider'], 'connections_org_provider_index');
        });
    }

    public function down(): void
    {
        Schema::table('connections', function (Blueprint $table): void {
            // Named explicitly. Letting the framework infer it here produced a different
            // name than the one created above on at least one engine, and the rollback
            // then failed on an index that "did not exist".
            $table->dropIndex('connections_org_provider_index');
            $table->dropColumn('provider');
        });
    }
};
