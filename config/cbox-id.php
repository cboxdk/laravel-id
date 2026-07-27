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

    /*
     * User API tokens (`cbid_pat_…`). A token issued without an explicit
     * expiry gets this TTL — no token is ever open-ended.
     */
    'user_api_tokens' => [
        'default_ttl_days' => env('CBOX_ID_USER_API_TOKEN_TTL_DAYS', 90),
    ],

    'webauthn' => [
        'rp_id' => env('CBOX_ID_WEBAUTHN_RP_ID'),
        'origin' => env('CBOX_ID_WEBAUTHN_ORIGIN'),
        // Require the user-verification flag on passkey ceremonies (PIN/biometric).
        // Keep true for passwordless (primary-factor) passkeys.
        'user_verification' => env('CBOX_ID_WEBAUTHN_USER_VERIFICATION', true),
    ],

    /*
     * The domain-event outbox (src/Kernel/Events/). Emitting writes a row; nothing is
     * delivered until the relay runs, so `schedule_relay` is what makes webhooks,
     * usage metering, outbound provisioning and every host listener actually fire.
     * Turn it off only if you drive EventBus::flushPending() yourself.
     *
     * `reclaim_after_seconds` is how long a claimed-but-undelivered event waits before
     * another relay may take it — i.e. how long we assume a relay that died mid-pass
     * might still be running.
     *
     * `relay_limit` and `relay_cadence` tune the scheduled pass without turning the
     * schedule off: a busy environment wants a larger batch, a quiet one a slower
     * tick. `relay_cadence` is a closed set (see RelayCadence) — every_minute,
     * every_two_minutes, every_five_minutes, every_ten_minutes,
     * every_fifteen_minutes, every_thirty_minutes, hourly — because a typo'd cron
     * string here would silently stop the entire fan-out.
     *
     * `max_attempts` bounds how many times a THROWING event is retried before it is
     * dead-lettered (`dead_lettered_at` stamped, never claimed again, logged at
     * critical). Unbounded retries are only right for a transient fault: a listener that
     * throws on data which will never change would otherwise be re-delivered on every
     * pass forever — never prunable, permanently counted as backlog, and skipping every
     * listener registered after it, for that event, on every pass.
     *
     * `backlog_warning_threshold` is the waiting depth at which each pass logs a
     * WARNING instead of a debug line. Relay lag is otherwise invisible: a stalled
     * relay looks exactly like an idle one. A host with metrics wiring can resolve
     * the RelayBacklog contract directly, or run `cbox-id:events:backlog` (the
     * package deliberately depends on no telemetry runtime).
     */
    'events' => [
        'schedule_relay' => env('CBOX_ID_EVENTS_SCHEDULE_RELAY', true),
        'relay_limit' => env('CBOX_ID_EVENTS_RELAY_LIMIT', 100),
        'relay_cadence' => env('CBOX_ID_EVENTS_RELAY_CADENCE', 'every_minute'),
        'reclaim_after_seconds' => env('CBOX_ID_EVENTS_RECLAIM_AFTER_SECONDS', 300),
        'max_attempts' => env('CBOX_ID_EVENTS_MAX_ATTEMPTS', 12),
        'backlog_warning_threshold' => env('CBOX_ID_EVENTS_BACKLOG_WARNING_THRESHOLD', 1000),
    ],

    /*
     * Webhook delivery. `verify_url` (SSRF guard) rejects endpoints that resolve
     * to loopback/private/link-local/reserved addresses and pins the connection
     * to the validated IPs (closing DNS-rebinding); keep it true in any
     * multi-tenant deployment. A single-tenant/on-prem install that legitimately
     * delivers to internal hosts may disable it. `max_attempts` bounds retries
     * before a delivery is dead-lettered (status `exhausted`). `schedule_retries`
     * registers a per-minute sweep that re-enqueues due failures; disable it if you
     * drive `retryPending()` yourself.
     *
     * Delivery is ASYNCHRONOUS: the relay records a delivery row per matching
     * endpoint and queues a DeliverWebhook job; the blocking HTTP send happens on a
     * worker. `queue_connection` / `queue` (both optional) put that egress on its
     * own connection/queue so a slow receiver cannot crowd out the rest of the
     * application's jobs. `retry_limit` caps how many due failures one sweep
     * re-enqueues, and `stranded_after_seconds` is how long a still-`pending`
     * delivery may sit before the sweep assumes its job was lost and re-enqueues
     * it — the row is durable BEFORE the job exists, and this is what makes that
     * guarantee real.
     *
     * `circuit_breaker` opens an endpoint after `failure_threshold` consecutive
     * failures and skips it for `cooldown_seconds`, so a blackholing receiver costs
     * one timeout per cooldown window instead of one per event. The trip is
     * recorded on the endpoint's health columns, NOT on `status` — `paused` stays
     * the operator's own intent.
     */
    /*
     * SCIM 2.0 service-provider discovery.
     *
     * `documentation_uri` is the OPTIONAL `documentationUri` of RFC 7643 §5 — an
     * HTTP-addressable page describing this deployment's SCIM support, which some
     * connectors surface to the operator during setup. It is UNSET by default and the
     * field is then omitted entirely: it used to be hard-coded to `<app>/docs`, a route
     * this package does not register and most hosts do not either, so the link that
     * appeared in a connector's setup screen led to a 404. An absent optional field is
     * correct; a present broken one is a promise the deployment cannot keep.
     */
    'scim' => [
        'documentation_uri' => env('CBOX_ID_SCIM_DOCUMENTATION_URI'),
    ],

    'webhooks' => [
        'verify_url' => env('CBOX_ID_WEBHOOKS_VERIFY_URL', true),
        'max_attempts' => env('CBOX_ID_WEBHOOKS_MAX_ATTEMPTS', 12),
        'schedule_retries' => env('CBOX_ID_WEBHOOKS_SCHEDULE_RETRIES', true),
        'retry_limit' => env('CBOX_ID_WEBHOOKS_RETRY_LIMIT', 50),
        'stranded_after_seconds' => env('CBOX_ID_WEBHOOKS_STRANDED_AFTER_SECONDS', 900),
        'queue_connection' => env('CBOX_ID_WEBHOOKS_QUEUE_CONNECTION'),
        'queue' => env('CBOX_ID_WEBHOOKS_QUEUE'),
        'circuit_breaker' => [
            'failure_threshold' => env('CBOX_ID_WEBHOOKS_CB_FAILURE_THRESHOLD', 5),
            'cooldown_seconds' => env('CBOX_ID_WEBHOOKS_CB_COOLDOWN_SECONDS', 300),
        ],
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
     * Access control — app authorization manifests. When an app publishes its
     * roles/permissions at a well-known URL, the platform PULLS it server-side, so
     * `verify_manifest_url` (SSRF guard) applies the same private/reserved/metadata
     * blocking + DNS-pinning as federation/webhooks. `fetch_timeout` bounds the
     * pull. Keep the guard true in any multi-tenant deployment.
     */
    'access_control' => [
        /*
         * RBAC driver — which authorization backend the platform (and its token
         * claims) reads from.
         *   'builtin'  — the package's own hierarchy-aware RBAC. Loads the
         *                roles/permissions/… schema and binds the built-in services.
         *   'external' — bring-your-own. The built-in tables and their migrations
         *                are NOT loaded, and AccessChecker/Roles fall back to a
         *                refusing default (deny-by-default) until you bind an adapter
         *                (e.g. one backed by an existing Spatie permission install).
         *                See docs/extension-points/custom-rbac.md.
         */
        'driver' => env('CBOX_ID_ACCESS_CONTROL_DRIVER', 'builtin'),

        'verify_manifest_url' => env('CBOX_ID_MANIFEST_VERIFY_URL', true),
        'fetch_timeout' => (int) env('CBOX_ID_MANIFEST_FETCH_TIMEOUT', 10),
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

        /*
         * How long (seconds) a host → environment resolution is cached.
         *
         * Every request resolves its environment before any endpoint logic runs, and
         * uncached that is 2–3 queries (custom domain, then slug, then the owning
         * account's liveness) against a table that changes approximately never.
         *
         * Invalidation is explicit, not TTL-driven, for everything that matters:
         * creating, renaming, re-domaining or suspending an environment, and
         * suspending or reactivating its account, all drop the entry immediately —
         * so the platform's off-switch still cuts traffic on the next request. The
         * TTL only bounds the one case that cannot be enumerated from the row: a
         * SLUG rename, where the old subdomain keeps resolving until it lapses.
         *
         * Set to 0 to disable caching entirely.
         */
        'resolution_cache_ttl' => env('CBOX_ID_ENVIRONMENT_RESOLUTION_CACHE_TTL', 60),
    ],

    /*
     * The IdP PROTOCOL surface this package registers — OIDC discovery, JWKS, the
     * RFC 8414 / RFC 9728 metadata, every `/oauth/*` endpoint, the SAML endpoints and
     * SCIM — and the extra middleware a HOST may wrap around all of it.
     *
     * EMPTY BY DEFAULT, deliberately: a single-tenant / self-hosted deployment is one
     * host that IS the identity provider, and it must keep serving the whole surface
     * with no configuration at all.
     *
     * A host application may serve more than identity providers. If one of its hosts is
     * a signup / account-management surface rather than an issuer, serving discovery
     * there publishes an `issuer` whose `authorization_endpoint` that host does not
     * answer — and a conformant client follows the document straight into a 404. Naming
     * middleware here lets the host 404 the entire surface on such a host using ITS OWN
     * answer to "is this host an identity provider", instead of this package growing a
     * second copy of that question that could disagree with the host's.
     *
     * Values are middleware aliases (e.g. `'plane:subject'`) or class names. They are
     * applied AFTER {@see \Cbox\Id\Api\Http\Middleware\ResolveEnvironment}, so a gate
     * can read the environment the request resolved to. `GET /up` is deliberately NOT
     * covered — a liveness probe must answer on every host.
     */
    'api' => [
        'middleware' => [],
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
            // `organizations` is advertised in discovery (scopes_supported) and the
            // token/UserInfo layer emits the claim, but it was missing here — so a
            // dynamically-registered client could never actually obtain it. Advertised
            // and unreachable is the same bug the grant list below fixed.
            'allowed_scopes' => ['openid', 'profile', 'email', 'offline_access', 'organizations'],
            /*
             * Grants a DYNAMICALLY registered client may ask for. device_code, CIBA and
             * token-exchange were advertised in discovery but absent here, so no
             * DCR-registered client could ever use them — advertised and unreachable.
             */
            'allowed_grant_types' => [
                'authorization_code',
                'refresh_token',
                'client_credentials',
                'urn:ietf:params:oauth:grant-type:device_code',
                'urn:openid:params:grant-type:ciba',
                'urn:ietf:params:oauth:grant-type:token-exchange',
            ],
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
         * Preferred over the absolute form above: a PATH, joined to the per-environment
         * issuer, so every tenant advertises its own authorize endpoint on its own host.
         * An absolute URL pins all environments to one host — wrong under multi-tenancy,
         * and it breaks mix-up-hardened clients because RFC 9207 is advertised with it.
         */
        'authorization_endpoint_path' => env('CBOX_ID_AUTHORIZATION_ENDPOINT_PATH'),

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

        /*
         * Access-token lifetime, in seconds. Access tokens carry roles + permissions
         * claims, so a SHORT lifetime is how authorization stays fresh: a revoked or
         * downgraded grant self-heals within one TTL, with no per-request revocation
         * check. Pair a short TTL with refresh tokens (which ARE revocable — see
         * RefreshTokens::revokeForUser) for instant effect on the next refresh.
         * Default 900s (15 min).
         */
        'access_token_ttl' => env('CBOX_ID_ACCESS_TOKEN_TTL', 900),

        /*
         * `POST /oauth/decisions` — the authorization decision endpoint.
         *
         * `max_batch` caps how many permission checks (and how many entitlement
         * keys) one request may ask for; past it the endpoint answers 422. Each
         * permission check walks the relationship graph with two queries per node up
         * to a depth of 12, so an uncapped array lets any holder of a valid token
         * turn one HTTP request into an unbounded number of database round trips.
         * Raise it if your clients legitimately batch more than a screen's worth,
         * but do not remove the bound.
         */
        'decisions' => [
            'max_batch' => env('CBOX_ID_DECISIONS_MAX_BATCH', 50),
        ],
    ],

    /*
     * SAML 2.0 Identity Provider (this platform acting AS the IdP that downstream
     * service providers — Salesforce, Workday, AWS, … — federate to).
     *
     * `entity_id` is the IdP EntityID published in metadata and set as the
     * assertion Issuer. It is an opaque URI and MUST stay stable once SPs have
     * imported it; leave null to derive `{issuer}/sso/saml/idp` — the derived
     * value is then FROZEN per environment on first publication, so verifying a
     * custom domain later moves the endpoint URLs but never the EntityID.
     *
     * `want_authn_requests_signed` pins the metadata attribute of the same name.
     * Leave null and it is derived from the registered SPs (true as soon as any
     * active SP requires signed AuthnRequests), which is what an SP that treats
     * metadata as authoritative — Shibboleth, Entra — needs to see.
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
        'want_authn_requests_signed' => env('CBOX_ID_SAML_IDP_WANT_AUTHN_REQUESTS_SIGNED'),
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
     * operation (distinct from webhooks, which only notify, async). The hook points:
     *
     *   token_minting         just before an access token is signed (every grant)
     *   post_login            after authentication, before the session is written
     *   pre_registration      before a subject is created (the signup gate)
     *   post_registration     just after, with the new subject id — notify only
     *   pre_password_change   before a credential is written
     *   post_password_change  just after — notify only
     *
     * `hooks` maps a hook point to a deny-by-default list of in-process Action
     * classes. External HTTP endpoints are registered at runtime via the
     * ExternalActions contract (SSRF-guarded, signed, sealed secret).
     *
     * `verify_url` toggles the SSRF guard on registered endpoints; `timeout` /
     * `connect_timeout` bound the synchronous call.
     *
     * FAIL POLICY — what happens when a hook cannot be CONSULTED (timeout, refused,
     * non-2xx). A hook that IS consulted and denies always denies; nothing here
     * changes that. Each point ships a default it can justify: the gates
     * (token_minting, pre_registration, pre_password_change) fail CLOSED, because a
     * security control that fails open is not a control; post_login fails OPEN,
     * because failing closed there means one customer's endpoint outage locks every
     * one of their users out of everything; the notify-only points fail open because
     * they have no decision to fail closed to.
     *
     * `fail_policy.<hook>` ('open' | 'closed') overrides one point. `fail_open`
     * (a bool) overrides ALL of them — leave it unset to keep the per-point defaults;
     * set it false to force every point closed, true to force every point open.
     *
     * `timeout` + `connect_timeout` is the WHOLE pipeline's budget, not each hook's:
     * a fan-out of several endpoints is issued concurrently, so registering a second
     * or third hook no longer adds its own timeout to every token mint. (A host that
     * has substituted a transport without concurrent support keeps the old
     * one-after-another behaviour, and with it the old additive cost.)
     *
     * `cache_ttl` (seconds) caches which endpoints are active per environment and
     * hook point. The token issuer consults the hook on EVERY mint, so without this
     * an environment that has registered no hooks at all still paid a query per
     * token. Registering, pausing, activating or removing an endpoint invalidates the
     * entry immediately, so the TTL is a backstop rather than the mechanism. Set to 0
     * to always read the database.
     */
    'external_actions' => [
        'verify_url' => env('CBOX_ID_ACTIONS_VERIFY_URL', true),
        'timeout' => env('CBOX_ID_ACTIONS_TIMEOUT', 3),
        'connect_timeout' => env('CBOX_ID_ACTIONS_CONNECT_TIMEOUT', 2),
        'cache_ttl' => env('CBOX_ID_ACTIONS_CACHE_TTL', 60),
        // Unset by default (null) so each hook point's own default applies; see above.
        'fail_open' => env('CBOX_ID_ACTIONS_FAIL_OPEN'),
        'fail_policy' => [
            // 'post_login' => 'closed',
        ],
        'hooks' => [
            // 'token_minting' => [ App\Actions\AddTenantTierClaim::class ],
            // 'pre_registration' => [ App\Actions\AllowlistedDomainsOnly::class ],
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
     * Data lifecycle (src/Maintenance/) — `cbox-id:prune`, scheduled daily.
     *
     * Every table below accumulates rows that stop being useful once they are past
     * their own expiry (replay guards, expired tokens, dispatched outbox rows) or
     * terminal (delivered/exhausted deliveries). Without a sweep they grow forever;
     * `dpop_proofs` in particular takes one INSERT per DPoP-protected request.
     *
     * `retention_days` is how long a row is kept AFTER it is already dead — not how
     * long a token lives. Set a table to null to keep its rows forever; omit a table
     * to use the default in Cbox\Id\Maintenance\Enums\PrunableTable.
     *
     * `audit_logs` is deliberately absent and is never pruned: it is a hash-chained,
     * checkpoint-anchored trail, and deleting rows would make its own tamper
     * verification report tampering. See Cbox\Id\Maintenance\Pruner.
     */
    'prune' => [
        'schedule' => env('CBOX_ID_PRUNE_SCHEDULE', true),
        'time' => env('CBOX_ID_PRUNE_TIME', '03:10'),
        'chunk' => env('CBOX_ID_PRUNE_CHUNK', 1000),

        'retention_days' => [
            'dpop_proofs' => env('CBOX_ID_PRUNE_DPOP_PROOFS', 1),
            'consumed_assertions' => env('CBOX_ID_PRUNE_CONSUMED_ASSERTIONS', 1),
            'oauth_authorization_codes' => env('CBOX_ID_PRUNE_AUTHORIZATION_CODES', 1),
            'oauth_access_tokens' => env('CBOX_ID_PRUNE_ACCESS_TOKENS', 7),
            'oauth_refresh_tokens' => env('CBOX_ID_PRUNE_REFRESH_TOKENS', 30),
            'events' => env('CBOX_ID_PRUNE_EVENTS', 30),
            'auth_sessions' => env('CBOX_ID_PRUNE_AUTH_SESSIONS', 30),
            'usage_metered_events' => env('CBOX_ID_PRUNE_USAGE_MARKERS', 30),
            'webhook_deliveries' => env('CBOX_ID_PRUNE_WEBHOOK_DELIVERIES', 30),
            'provisioning_operations' => env('CBOX_ID_PRUNE_PROVISIONING_OPERATIONS', 30),
        ],
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
