<?php

declare(strict_types=1);
use Cbox\Id\Identity\Models\User;

return [

    /*
     * The token issuer / base URL, published in OIDC discovery and used to build
     * endpoint URLs. Falls back to the app URL when unset.
     */
    'issuer' => env('CBOX_ID_ISSUER'),

    /*
     * Override a package model with your own subclass to add relations, casts or
     * behaviour. Your class must extend the package model; the platform still owns
     * the schema. Extend the pattern to other models as you need them.
     */
    'models' => [
        'user' => User::class,
    ],

    /*
     * WebAuthn / passkey ceremony parameters. `rp_id` is the Relying Party ID
     * (usually your registrable domain, e.g. "example.com"); `origin` is the
     * exact origin the browser reports (scheme + host + port). Both are asserted
     * during verification — a mismatch is rejected.
     */
    'webauthn' => [
        'rp_id' => env('CBOX_ID_WEBAUTHN_RP_ID'),
        'origin' => env('CBOX_ID_WEBAUTHN_ORIGIN'),
    ],

    'crypto' => [

        /*
         * Master key for envelope encryption (SecretBox). A base64-encoded,
         * 32-byte key. Generate one with:
         *
         *     php -r "echo base64_encode(random_bytes(32)).PHP_EOL;"
         *
         * Losing this key makes all sealed secrets (including private signing
         * keys) unrecoverable. Back it up separately from the database.
         */
        'key' => env('CBOX_ID_CRYPTO_KEY'),

    ],

];
