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
     * How the platform resolves "the user". By default it uses a self-contained
     * store over its own users table (`models.user`). To integrate with an app
     * that already has users — including several authenticatable models (users,
     * admins, resellers) or a single model with role flags — set `resolver` to
     * your own class implementing Cbox\Id\Identity\Contracts\Subjects. The
     * platform only ever references a subject by its opaque id.
     */
    'subject' => [
        'resolver' => null,
    ],

    /*
     * Table names the platform reads/writes. Point `users` at your existing user
     * table to integrate with an app that already has one; the platform does not
     * create this table automatically (see the optional cbox-id-users-migration).
     */
    'tables' => [
        'users' => 'users',
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
        // Require the user-verification flag on passkey ceremonies (PIN/biometric).
        // Keep true for passwordless (primary-factor) passkeys.
        'user_verification' => env('CBOX_ID_WEBAUTHN_USER_VERIFICATION', true),
    ],

    /*
     * Webhook delivery. `verify_url` (SSRF guard) rejects endpoints that resolve
     * to loopback/private/link-local/reserved addresses; keep it true in any
     * multi-tenant deployment. A single-tenant/on-prem install that legitimately
     * delivers to internal hosts may disable it.
     */
    'webhooks' => [
        'verify_url' => env('CBOX_ID_WEBHOOKS_VERIFY_URL', true),
    ],

    /*
     * OAuth 2.0 Dynamic Client Registration (RFC 7591) and client management
     * (RFC 7592). MCP clients rely on DCR to self-register.
     *
     * mode:
     *   'disabled'  — /oauth/register returns 403 and is not advertised (default,
     *                 secure-by-default: open registration is an abuse surface).
     *   'protected' — registration requires an initial access token (bearer)
     *                 matching `initial_access_token`.
     *   'open'      — anyone may register (rate-limited). Suitable for public MCP
     *                 deployments that expect unknown clients.
     *
     * allowed_scopes limits what a dynamically registered client may request; a
     * requested scope outside this list is dropped. grant_types listed here are
     * the only ones a dynamic client may be granted.
     */
    'oauth' => [
        'dynamic_registration' => [
            'mode' => env('CBOX_ID_DCR_MODE', 'disabled'),
            'initial_access_token' => env('CBOX_ID_DCR_INITIAL_ACCESS_TOKEN'),
            'allowed_scopes' => ['openid', 'profile', 'email', 'offline_access'],
            'allowed_grant_types' => ['authorization_code', 'refresh_token', 'client_credentials'],
        ],
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
