<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * An API — a resource server — and the scopes it owns.
 *
 * Until this table existed a scope was free text on each client. Nothing said which
 * resource server a scope belonged to or who was allowed to hand it out, so an
 * organization administrator could type `tax:assess` onto their own client and ask for a
 * token audienced to the tax API with it. `resource` was checked only for being an
 * absolute URI before it became `aud`, so the token said exactly what the tax API was
 * waiting to read, signed by us.
 *
 * AN API IS AN AUDIENCE WITH AN OWNER. `identifier` is what lands in `aud`; it is unique
 * per environment, because two resource servers answering to one audience is the
 * confused-deputy problem again. `organization_id` null means the environment owns it;
 * a value means one tenant does. `client_id` optionally names the app whose manifest
 * roles and permissions the API enforces, so a token minted FOR the API carries the
 * API's authorization rather than the requesting client's.
 *
 * SCOPE KEYS ARE UNIQUE PER ENVIRONMENT, NOT PER API. A scope is looked up by key alone
 * at issuance — the request says `scope=tax:assess`, not which API it meant — so two APIs
 * owning the same key would make every such request ambiguous, and the ambiguity would
 * be resolved by whichever row the database returned first.
 *
 * `tenant_requestable` is the per-scope answer to "may a client owned by an organization
 * hold this?" It only matters for an environment-owned API: a tenant's own API is always
 * requestable by that tenant's clients and never by anyone else's.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oauth_apis', function (Blueprint $table): void {
            // `string(…, 26)`, never `ulid()` — see SchemaPortabilityTest: CHAR comes
            // back blank-padded on PostgreSQL and a strict comparison is then false.
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();
            $table->string('organization_id', 26)->nullable()->index();

            // Full width, not 26: a client id is `cid_` + a ULID.
            $table->string('client_id')->nullable()->index();

            $table->string('identifier', 255);
            $table->string('name', 120);
            $table->timestamps();

            $table->unique(['environment_id', 'identifier']);
        });

        Schema::create('oauth_api_scopes', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26);
            $table->string('api_id', 26)->index();
            $table->string('key', 128);
            $table->string('description', 255)->nullable();
            $table->boolean('tenant_requestable')->default(true);
            $table->timestamps();

            $table->unique(['environment_id', 'key']);

            // A scope row outliving its API would be a registered scope with no
            // audience — one the resolver could never place and never grant.
            $table->foreign('api_id')->references('id')->on('oauth_apis')->cascadeOnDelete();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oauth_api_scopes');
        Schema::dropIfExists('oauth_apis');
    }
};
