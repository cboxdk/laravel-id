<?php

declare(strict_types=1);
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Otp\Channels\EmailOtpChannel;

return [

    /*
     * The token issuer / base URL, published in OIDC discovery and used to build
     * endpoint URLs. Falls back to the app URL when unset.
     */
    'issuer' => env('CBOX_ID_ISSUER'),

    /*
     * On-prem licensing. A signed, offline-verifiable license key unlocks paid /
     * enterprise entitlements deployment-wide through the entitlement gate — no
     * phone-home. Leave both blank for the free single-tenant tier.
     *
     *   key         — the license token the customer installs (CBOX_ID_LICENSE_KEY).
     *   public_key  — base64 Ed25519 public key the app verifies against; bake the
     *                 issuer's public key in here (safe to ship). Generate a keypair
     *                 with `php artisan id:license:keygen`.
     *   domain      — optional host the license is bound to (defaults to the issuer
     *                 host); a domain-bound key only unlocks on that host.
     */
    'license' => [
        'key' => env('CBOX_ID_LICENSE_KEY'),
        'public_key' => env('CBOX_ID_LICENSE_PUBLIC_KEY'),
        'domain' => env('CBOX_ID_LICENSE_DOMAIN'),
    ],

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
     * SIEM audit streaming (src/AuditStreaming/). Mirrors the hash-chained,
     * environment-scoped audit trail out to a customer's SIEM by composing
     * cboxdk/laravel-siem's delivery engine over ENVIRONMENT-OWNED stream/outbox
     * models — so isolation is inherited from the hard environment scope, never
     * re-implemented. The engine itself is configured under the `siem.*` namespace
     * (published from cboxdk/laravel-siem: batching, retry/dead-letter, circuit
     * breaker, backpressure, HTTP egress). This package forces three of those keys
     * and owns none of the rest:
     *   - siem.models.log_stream      → AuditStream (env-owned)
     *   - siem.models.stream_delivery → AuditStreamDelivery (env-owned)
     *   - siem.schedule.enabled       → false (laravel-id schedules the pump, so it
     *                                   can reconstruct each stream's environment)
     *
     * SECURITY: `siem.http.verify_url` (the SSRF guard) and `siem.http.tls_verify`
     * are operator-only. NEVER expose either to a tenant/org admin — a tenant that
     * could disable the SSRF guard could point a stream at an internal address.
     *
     * `schedule` registers the per-minute pump that fans a delivery job out to every
     * enabled stream across all environments; disable it to run
     * `cbox-id:audit-streams:pump` yourself.
     */
    'audit_streaming' => [
        'schedule' => env('CBOX_ID_AUDIT_STREAMING_SCHEDULE', true),
    ],

    /*
     * Outbound SCIM 2.0 provisioning (src/Provisioning/). The mirror of the
     * inbound Directory (SCIM server): when a user or membership changes, the
     * platform pushes the change OUT to each org's downstream SaaS apps via THEIR
     * SCIM endpoints (create/update/deactivate the remote user).
     *
     * `verify_url` (SSRF guard) rejects a downstream SCIM base URL or OAuth token
     * URL that resolves to loopback/private/link-local/reserved addresses and pins
     * the connection to the validated IPs (closing DNS-rebinding) — the same guard
     * webhooks and federation use. Keep it true in any multi-tenant deployment; a
     * single-tenant/on-prem install delivering to an internal SCIM endpoint may
     * disable it. `max_attempts` bounds retries before an operation is dead-lettered
     * (status `exhausted`); `batch_limit` caps how many operations one drain pass
     * ships per connection. `circuit_breaker` opens a connection after
     * `failure_threshold` consecutive transient failures and pauses it for
     * `cooldown_seconds`, so a failing downstream app never blocks the others.
     * `schedule` registers the per-minute drain that fans a job out to every active
     * connection across all environments; disable it to run
     * `cbox-id:provisioning:drain` yourself.
     */
    'provisioning' => [
        'verify_url' => env('CBOX_ID_PROVISIONING_VERIFY_URL', true),
        'max_attempts' => env('CBOX_ID_PROVISIONING_MAX_ATTEMPTS', 12),
        'batch_limit' => env('CBOX_ID_PROVISIONING_BATCH_LIMIT', 50),
        'schedule' => env('CBOX_ID_PROVISIONING_SCHEDULE', true),
        'circuit_breaker' => [
            'failure_threshold' => env('CBOX_ID_PROVISIONING_CB_FAILURE_THRESHOLD', 5),
            'cooldown_seconds' => env('CBOX_ID_PROVISIONING_CB_COOLDOWN_SECONDS', 300),
        ],
    ],

    /*
     * Federation (inbound SSO). `verify_url` (SSRF guard) applies the same
     * loopback/private/link-local/reserved blocking and DNS-pinning as webhook
     * delivery to org-admin-configured outbound IdP endpoints (e.g. an OIDC
     * `token_endpoint`) that the platform fetches server-side. Keep it true in any
     * multi-tenant deployment; a single-tenant/on-prem install that must reach an
     * internal IdP may disable it.
     */
    'federation' => [
        'verify_url' => env('CBOX_ID_FEDERATION_VERIFY_URL', true),
    ],

    /*
     * Environments — the hard identity boundary resolved per request from the host
     * (own users, signing keys, issuer). When the host maps to none, the fallback
     * plane is used: the environment flagged `is_default` in the database (the
     * primary mechanism — set once by `cbox-id:install`, held across every replica
     * with no writable .env). This `default` config key is an OPTIONAL override
     * that wins when set — an explicit environment key via env var / ConfigMap.
     * Leave both unset in a multi-tenant deployment (an unknown host is refused).
     */
    'environments' => [
        'default' => env('CBOX_ID_ENVIRONMENT_DEFAULT'),

        /*
         * Base domains under which a subdomain resolves to an environment by its
         * leading label (e.g. `staging.auth.example.com` → the `staging` plane).
         * A host is only trusted for slug resolution when it sits under one of
         * these — so a spoofed Host like `staging.attacker.com` can never select a
         * plane. Leave empty to require an exact custom-domain match. Comma list
         * via env, or an array here.
         */
        'base_domains' => array_filter(array_map(
            'trim',
            explode(',', (string) env('CBOX_ID_ENVIRONMENT_BASE_DOMAINS', '')),
        )),
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
         * The interactive authorization endpoint (OIDC/OAuth `/authorize`) is the
         * HOST app's responsibility — this package serves the back-channel token,
         * introspection, revocation and PAR endpoints, not the user-facing consent
         * screen. Set this to the absolute URL where the host mounts `/authorize`
         * and it is advertised in discovery metadata; leave it null (default) and
         * the `authorization_endpoint` key is omitted rather than pointing at a
         * route the package does not serve (RFC 8414 allows omitting it).
         */
        'authorization_endpoint' => env('CBOX_ID_AUTHORIZATION_ENDPOINT'),

        /*
         * FAPI baseline: require every authorization request to be pushed
         * (RFC 9126) so parameters never ride the browser URL. Turning this on is
         * one of the switches in the FAPI hardening profile — see docs/fapi.md.
         */
        'require_par' => env('CBOX_ID_REQUIRE_PAR', false),

        /*
         * OpenID Connect CIBA (Client-Initiated Backchannel Authentication), poll
         * mode — the human-in-the-loop approval grant for autonomous / AI agents.
         * `ttl_seconds` is the approval window (and the ceiling on a client's
         * requested_expiry); `poll_interval` is the minimum seconds between token
         * polls (enforced with `slow_down`). The user notification + approval UI is
         * the host's; the package emits `oauth.backchannel_authentication_requested`.
         */
        'ciba' => [
            'ttl_seconds' => env('CBOX_ID_CIBA_TTL_SECONDS', 300),
            'poll_interval' => env('CBOX_ID_CIBA_POLL_INTERVAL', 5),
        ],

        /*
         * Hybrid entitlements: embed the coarse, Claims-mode entitlements in the
         * access token (`ent` claim) so resource servers can gate statelessly.
         * Instant-critical entitlements stay DecisionApi (live via /oauth/decisions)
         * regardless. Turn off to keep tokens free of entitlement claims entirely.
         */
        'embed_entitlements' => env('CBOX_ID_EMBED_ENTITLEMENTS', true),
    ],

    /*
     * SAML 2.0 Identity Provider (this platform acting AS the IdP that downstream
     * service providers — Salesforce, Workday, AWS, … — federate to).
     *
     * `entity_id` is the IdP EntityID published in metadata and set as the
     * assertion Issuer. It is an opaque URI and MUST stay stable once SPs have
     * imported it; leave null to derive `{issuer}/sso/saml/idp`.
     *
     * `login_url` is where the SingleSignOnService endpoint sends a browser that
     * has no authenticated subject yet — the host's own login screen. The endpoint
     * appends `return_to` so the host can re-dispatch the SSO request after the
     * user signs in. Leave null and an unauthenticated SSO request is answered
     * with 401 (the host is expected to drive the flow itself).
     */
    'saml_idp' => [
        'entity_id' => env('CBOX_ID_SAML_IDP_ENTITY_ID'),
        'login_url' => env('CBOX_ID_SAML_IDP_LOGIN_URL'),
    ],

    /*
     * Password-hash verification for bulk import + lazy migration. The platform
     * verifies stored password hashes through a DENY-BY-DEFAULT registry: a hash
     * whose format no registered verifier understands is REFUSED, never a silent
     * pass. The package ships only the native verifier (bcrypt + argon2, via PHP's
     * vetted password_verify). To accept a foreign format when migrating off
     * another provider — Firebase scrypt, PBKDF2, an LDAP {SSHA} digest — add your
     * own class implementing Cbox\Id\Identity\Contracts\HashVerifier (wrapping a
     * vetted library; never hand-roll the primitive). Once a user with such a hash
     * signs in successfully, their password is transparently re-hashed with the
     * platform hasher (see Subjects::verifyPassword()), so the foreign format is
     * needed only during the migration window.
     */
    'hashing' => [
        'verifiers' => [
            // App\Auth\FirebaseScryptVerifier::class,
        ],
    ],

    /*
     * Delivered one-time passcodes (src/Otp/) — email/SMS codes as a verification
     * or MFA factor. Security note: a short numeric code lives in a ~10^length
     * space, so its safety rests on these CAPS, not on the code's entropy —
     * `ttl_seconds`, `max_attempts`, and the two rate limits are the real controls.
     *
     * `channels` is the DENY-BY-DEFAULT sender registry (`key => OtpChannel class`).
     * A key with no registered sender is refused, never a silent no-op. The package
     * ships `email` (framework mailer) and `log` (DEV-ONLY: writes the code to the
     * log). SMS is a CONTRACT ONLY — register your provider's channel here (see
     * docs/cookbook/add-an-sms-otp-channel.md); this package ships no SMS SDK.
     *
     * `issue` throttles issuance: `max_per_window` per recipient+purpose+IP, and
     * `per_recipient_max` per recipient ACROSS all purposes and IPs — the latter is
     * what bounds SMS-bombing when an attacker rotates IPs or purposes. `verify`
     * throttles verification: `max_per_window` globally per IP, and
     * `per_recipient_max` per recipient+purpose across IPs (anti-brute-force). A
     * short numeric code is only safe because of these caps, not its entropy.
     */
    'otp' => [
        // Minimum enforced length is 6 digits (see OtpServiceProvider::clampedLength).
        'code_length' => env('CBOX_ID_OTP_CODE_LENGTH', 6),
        'ttl_seconds' => env('CBOX_ID_OTP_TTL_SECONDS', 300),
        'max_attempts' => env('CBOX_ID_OTP_MAX_ATTEMPTS', 5),

        'issue' => [
            'max_per_window' => env('CBOX_ID_OTP_ISSUE_MAX', 5),
            'per_recipient_max' => env('CBOX_ID_OTP_ISSUE_RECIPIENT_MAX', 10),
            'window_seconds' => env('CBOX_ID_OTP_ISSUE_WINDOW', 3600),
        ],

        'verify' => [
            'max_per_window' => env('CBOX_ID_OTP_VERIFY_MAX', 20),
            'per_recipient_max' => env('CBOX_ID_OTP_VERIFY_RECIPIENT_MAX', 15),
            'window_seconds' => env('CBOX_ID_OTP_VERIFY_WINDOW', 900),
        ],

        'channels' => [
            'email' => EmailOtpChannel::class,
            // Local development only — logs the plaintext code. Never enable in prod.
            // 'log' => Cbox\Id\Otp\Channels\LogOtpChannel::class,
            // Register your own channel wrapping an SMS provider (Twilio, etc.):
            // 'sms' => App\Otp\SmsOtpChannel::class,
        ],

        'email' => [
            'subject' => env('CBOX_ID_OTP_EMAIL_SUBJECT', 'Your verification code'),
            'from' => [
                'address' => env('CBOX_ID_OTP_EMAIL_FROM_ADDRESS'),
                'name' => env('CBOX_ID_OTP_EMAIL_FROM_NAME'),
            ],
        ],
    ],

    /*
     * External actions / inline hooks (src/ExternalActions/) — synchronous extension
     * points where the platform consults registered logic that can ENRICH or VETO an
     * operation (distinct from webhooks, which only notify, async). v1 ships the
     * `token.minting` hook: run just before an access token is signed.
     *
     * `hooks` maps a hook point to a deny-by-default list of in-process Action
     * classes. External HTTP endpoints are registered at runtime via the
     * ExternalActions contract (SSRF-guarded, signed, sealed secret).
     *
     * `verify_url` toggles the SSRF guard on registered endpoints; `timeout` /
     * `connect_timeout` bound the synchronous call. `fail_open` decides what happens
     * when a hook cannot be run: the default (false) FAILS CLOSED — a security
     * control that fails open is not a control — at the cost of availability if the
     * hook endpoint is down. Set it true only for enrichment-only hooks.
     */
    'external_actions' => [
        'verify_url' => env('CBOX_ID_ACTIONS_VERIFY_URL', true),
        'timeout' => env('CBOX_ID_ACTIONS_TIMEOUT', 3),
        'connect_timeout' => env('CBOX_ID_ACTIONS_CONNECT_TIMEOUT', 2),
        'fail_open' => env('CBOX_ID_ACTIONS_FAIL_OPEN', false),
        'hooks' => [
            // 'token_minting' => [ App\Actions\AddTenantTierClaim::class ],
        ],
    ],

    /*
     * Access governance (src/Governance/) — Identity Governance & Administration.
     * Access-certification campaigns (periodic review of who holds which role /
     * membership, with reviewer certify/revoke decisions applied on close) and
     * Segregation-of-Duties policies (a pre-grant gate + a detector for toxic role
     * combinations). All environment-owned, deny-by-default, and audited.
     *
     * `schedule` runs `cbox-id:governance:close-overdue` every minute to auto-close
     * campaigns past their due date. Turn it off to drive the command by hand.
     */
    'governance' => [
        'schedule' => env('CBOX_ID_GOVERNANCE_SCHEDULE', true),
    ],

    /*
     * Usage metering (src/Kernel/Usage/) — records meaningful events as environment-
     * and organization-scoped per-day counters, the MEASUREMENT layer a usage
     * dashboard renders and future plan gates read. When enabled, domain events are
     * auto-metered off the outbox (exactly-once). Disable to skip all metering — no
     * counter or marker writes are made.
     */
    'usage' => [
        'enabled' => env('CBOX_ID_USAGE_ENABLED', true),
    ],

    /*
     * AI token vault (src/TokenVault/) — holds downstream third-party credentials
     * (API keys, OAuth tokens for services an AI agent calls) SEALED at rest via
     * the Crypto SecretBox, and brokers short-lived, deny-by-default leased access
     * to agent clients. A lease returns the plaintext to an AUTHORIZED client for
     * immediate use and audits every access — never the value. Access needs an
     * explicit, revocable grant (client_id → secret); no grant means refused.
     *
     * `default_lease_ttl_seconds` is the vault-wide ceiling on how long a leased
     * secret may be held; a per-grant `max_ttl_seconds` can only shorten it.
     */
    'token_vault' => [
        'default_lease_ttl_seconds' => env('CBOX_ID_VAULT_LEASE_TTL', 300),
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
