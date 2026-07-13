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
    /*
     * Session lifetimes. `ttl_minutes` is the absolute cap; `idle_minutes` (0 to
     * disable) expires a session after inactivity, with a sliding window that is
     * refreshed on use. Secure defaults for an admin console lean short.
     */
    'sessions' => [
        'ttl_minutes' => env('CBOX_ID_SESSION_TTL_MINUTES', 60 * 8),
        'idle_minutes' => env('CBOX_ID_SESSION_IDLE_MINUTES', 30),
    ],

    'webauthn' => [
        'rp_id' => env('CBOX_ID_WEBAUTHN_RP_ID'),
        'origin' => env('CBOX_ID_WEBAUTHN_ORIGIN'),
        // Require the user-verification flag on passkey ceremonies (PIN/biometric).
        // Keep true for passwordless (primary-factor) passkeys.
        'user_verification' => env('CBOX_ID_WEBAUTHN_USER_VERIFICATION', true),
    ],

    /*
     * Webhook delivery. `verify_url` (SSRF guard) rejects endpoints that resolve
     * to loopback/private/link-local/reserved addresses and pins the connection
     * to the validated IPs (closing DNS-rebinding); keep it true in any
     * multi-tenant deployment. A single-tenant/on-prem install that legitimately
     * delivers to internal hosts may disable it. `max_attempts` bounds retries
     * before a delivery is dead-lettered (status `exhausted`). `schedule_retries`
     * registers a per-minute task that redelivers due failures; disable it if you
     * drive `retryPending()` yourself.
     */
    'webhooks' => [
        'verify_url' => env('CBOX_ID_WEBHOOKS_VERIFY_URL', true),
        'max_attempts' => env('CBOX_ID_WEBHOOKS_MAX_ATTEMPTS', 12),
        'schedule_retries' => env('CBOX_ID_WEBHOOKS_SCHEDULE_RETRIES', true),
    ],

    /*
     * Environments — the hard identity boundary resolved per request from the host
     * (own users, signing keys, issuer). `default` is the fallback environment key
     * used when the host maps to none: set it for single-tenant / on-prem, or leave
     * null for a multi-tenant deployment (an unknown host is then refused).
     */
    'environments' => [
        'default' => env('CBOX_ID_ENVIRONMENT_DEFAULT'),
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

        /*
         * FAPI baseline: require every authorization request to be pushed
         * (RFC 9126) so parameters never ride the browser URL. Turning this on is
         * one of the switches in the FAPI hardening profile — see docs/fapi.md.
         */
        'require_par' => env('CBOX_ID_REQUIRE_PAR', false),

        /*
         * Hybrid entitlements: embed the coarse, Claims-mode entitlements in the
         * access token (`ent` claim) so resource servers can gate statelessly.
         * Instant-critical entitlements stay DecisionApi (live via /oauth/decisions)
         * regardless. Turn off to keep tokens free of entitlement claims entirely.
         */
        'embed_entitlements' => env('CBOX_ID_EMBED_ENTITLEMENTS', true),
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
