<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * A key a browser is ALLOWED to hold, and the origins that may hold it.
 *
 * Every credential this product has issued so far is a secret: a client secret, an API
 * key, a service-account credential. All of them share one rule — never put this in a
 * browser — and that rule is why the SDK components are redirect shells. A page that
 * cannot authenticate itself to us cannot render a sign-in form, so it sends the person
 * away to a hosted page and waits for them to come back.
 *
 * A publishable key inverts the rule deliberately. It is PUBLIC. It ships in a JS bundle,
 * it appears in devtools, it is in the page source of every customer who uses it, and
 * none of that is a compromise, because it authenticates almost nothing: it names an
 * environment, and it says "a browser is asking". Everything it can reach is either
 * public by nature (how do I theme the sign-in box) or already gated by something else
 * (a session cookie the browser had anyway).
 *
 * SO THE ORIGIN IS THE REAL CREDENTIAL. `frontend_api_origins` is an allow-list, and a
 * request whose `Origin` is not on it is refused before anything else runs. That is what
 * stops a stolen key being useful: it can be read by anyone and used only from the sites
 * its owner named. This is the same shape as Stripe's publishable key + registered
 * domains, and for the same reason.
 *
 * TWO MODES, NOT ONE. `pk_test_` and `pk_live_` are different keys against different
 * environments, and a person can tell at a glance which one is pasted into a staging
 * bundle. A single key with a boolean would be one config mistake away from a test page
 * driving production sign-ins.
 *
 * NOT HASHED AT REST, which is the opposite of every other credential table here and is
 * intentional. A hash would buy nothing — the value is printed in the customer's own HTML
 * — and would cost the lookup, since every request arrives keyed by it. Hashing a public
 * value is a ritual that makes an audit trail look thorough while making the system
 * slower and the code harder to read.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('frontend_api_keys', function (Blueprint $table): void {
            // `string(…, 26)`, never `ulid()`: Laravel's helper compiles to CHAR, and
            // PostgreSQL implements CHAR as blank-padded `bpchar`, so a value comes back
            // padded and a strict comparison against it is false. SchemaPortabilityTest
            // holds this, and it cost 338 failures once.
            $table->string('id', 26)->primary();
            $table->string('environment_id', 26)->index();

            // Unique across the install, not per environment: it is the whole lookup, and
            // a collision would silently point one customer's browser at another's
            // environment. `pk_live_` + 32 base62 — the prefix is for humans, the entropy
            // is the rest.
            $table->string('key', 64)->unique();
            $table->string('mode', 8);

            // What a person calls it in the console. "Marketing site", "iOS webview".
            $table->string('name', 120);

            $table->timestamp('last_used_at')->nullable();

            // Revocation is a timestamp rather than a delete, so a key that turns up in a
            // log six months later can still be identified as one we withdrew, and when.
            $table->timestamp('revoked_at')->nullable();

            $table->timestamps();
        });

        Schema::create('frontend_api_origins', function (Blueprint $table): void {
            $table->string('id', 26)->primary();
            $table->string('frontend_api_key_id', 26)->index();

            // A SERIALIZED ORIGIN — scheme://host[:port], no path, no trailing slash. It is
            // compared byte-for-byte against the request's `Origin` header, because every
            // clever comparison anyone has ever written for this (suffix match, wildcard
            // subdomain, "starts with https://") has been the bug. `https://acme.com`
            // matching `https://acme.com.evil.test` is the classic, and it is a suffix
            // match away.
            $table->string('origin', 255);

            $table->timestamps();

            $table->unique(['frontend_api_key_id', 'origin']);

            // The cascade is declared rather than left to the application: an origin row
            // outliving its key is a row nothing can reach and nothing will clean up.
            $table->foreign('frontend_api_key_id')->references('id')->on('frontend_api_keys')->cascadeOnDelete();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('frontend_api_origins');
        Schema::dropIfExists('frontend_api_keys');
    }
};
