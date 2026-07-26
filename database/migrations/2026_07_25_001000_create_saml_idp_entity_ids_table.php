<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // The IdP EntityID this environment has PUBLISHED, frozen at first use.
        //
        // The EntityID is derived from the environment's issuer, and the issuer
        // follows the host — so verifying a custom domain silently changed the
        // EntityID, and every SP that had imported the old one rejected the next
        // assertion with "Issuer does not match", simultaneously, with no warning
        // anywhere in the domain-verification flow. An EntityID is an opaque,
        // permanent name: it is frozen here the first time it is published and
        // read back from this row afterwards, while the endpoint URLs stay free
        // to follow the host.
        Schema::create('saml_idp_entity_ids', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id');
            $table->text('entity_id');
            $table->timestamps();

            // One frozen EntityID per environment — the uniqueness IS the freeze.
            $table->unique('environment_id');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('saml_idp_entity_ids');
    }
};
