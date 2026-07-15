# Changelog

All notable changes to `cboxdk/laravel-id` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Confirmed security vulnerabilities and their fixes are cross-referenced under
**Security** below and in the repository's security advisories.

## [0.10.0] - 2026-07-15

### Added

- **Outbound SCIM 2.0 provisioning (`src/Provisioning/`).** The mirror of the
  inbound Directory module: the platform acting as a SCIM **client**, pushing user
  and membership changes OUT to an organization's downstream apps over THEIR SCIM
  2.0 endpoints (create/update/deactivate the remote user). No new runtime
  dependency — it reuses the existing HTTP client, `cboxdk/laravel-ssrf`, the Crypto
  kernel and the domain event bus.
  - **Shared SCIM schema (`Cbox\Id\Scim\ScimSchema`).** The RFC 7643/7644 URNs and
    pure body builders (`User` resource, `PatchOp`, `ListResponse`, error, equality
    filter) were extracted into one transport-agnostic source of truth, now consumed
    by BOTH the inbound `Api\Support\ScimMapper` (which was refactored to reference
    it, no behaviour change) and the new outbound client — the URNs are declared
    once, not duplicated per direction.
  - **`Contracts\ScimClient` + `HttpScimClient` (new contract).** The outbound SCIM
    2.0 HTTP client: `POST /Users` (create → capture the remote id), `PATCH
    /Users/{id}` with a `PatchOp` body (update / `replace active`), `DELETE
    /Users/{id}`, and `GET /Users?filter=externalId eq "…"` for reconcile. Every
    request is SSRF-guarded and IP-pinned immediately before connect (redirects
    refused), TLS-verified, and carries `application/scim+json`. Bearer or OAuth 2.0
    client-credentials auth is opened from the sealed secret; the token is never
    placed in a returned result or a stored error.
  - **`Contracts\ProvisioningConnections` + `DatabaseProvisioningConnections` (new
    contract).** The registry of downstream targets. Registration SSRF-checks the
    base URL and seals the secret (reveal-once); `inScopeFor()` resolves the
    connections in the current environment that a given change belongs to.
  - **`Contracts\ProvisioningService` + `OutboxProvisioningService` (new contract).**
    Translates a domain event to a SCIM operation and enqueues a durable outbox row
    per in-scope connection, then drains it statefully — POST vs. PATCH is decided by
    the captured remote id, a 409-on-create reconciles by `externalId`, a 404-on-update
    recreates. Bounded exponential backoff + jitter, a dead-letter cap, and a
    per-connection circuit breaker.
  - **Environment-owned models (`Models\ProvisioningConnection`,
    `Models\ProvisionedResource`, `Models\ProvisioningOperation`).** All
    `BelongsToEnvironment`, so cross-environment provisioning is structurally
    impossible. `ProvisionedResource` (unique per environment+connection+user) is the
    SCIM statefulness — the platform user ↔ remote resource id mapping. A migration
    adds the three tables.
  - **Event-driven, async delivery.** `Listeners\ProvisionOnDomainEvent` enqueues on
    every `EventDelivered` (request thread, never delivers). `Jobs\DrainProvisioningConnection`
    (`ShouldBeUnique` per connection) drains in a worker, reconstructing the
    connection's environment (`EnvironmentContext::withoutScope()` single-id read →
    `runAs()`) exactly as the audit-streaming pump does. `Console\DrainProvisioningCommand`
    (scheduled per-minute, mirroring the Webhooks retry schedule) fans a drain out to
    every active connection across all environments; `Console\SyncProvisioningCommand`
    (`cbox-id:provisioning:sync {--connection=}`) reconciles in-scope subjects.
  - **Attribute mapping (`Support\AttributeMapping`).** Maps platform attributes onto
    SCIM `User` paths, defaulting to userName/email/displayName and supporting the
    Enterprise User extension; rebind per connection or via the contract.
  - **Config.** New `cbox-id.provisioning.*` keys: `verify_url` (SSRF, operator-only),
    `max_attempts`, `batch_limit`, `schedule`, and `circuit_breaker.*`.
  - **Testing.** `Testing\InteractsWithProvisioning` + an in-memory `Testing\FakeScimClient`
    (a conformant fake downstream SCIM server) — dogfooded by the suite, which proves
    the lifecycle against real RFC 7643/7644 payload shapes, the 409/404 reconcile
    paths, cross-environment isolation at both dispatch and drain, retry/dead-letter,
    the circuit breaker, deny-by-default, SSRF refusal and secret-at-rest.

### Security

- Outbound provisioning egress is SSRF-guarded and DNS-pinned on every request
  (SCIM base URL and OAuth token URL), TLS-verify on, with connection secrets sealed
  at rest (reveal-once) and scrubbed from errors/dead-letter rows. Environment-owned
  models keep provisioning deny-by-default and single-environment. Delivery is
  documented as at-least-once (not exactly-once); no unverified SCIM-conformance
  claim is made beyond what the tests exercise.
- **Adversarial review — three defects found and fixed before release:**
  - **No longer deprovisions a still-entitled user.** `organization.member_removed`
    now deprovisions ONLY connections the user has genuinely LEFT
    (`ProvisioningConnections::leftScopeFor()`): an org-scoped connection only when no
    remaining membership keeps the user in its scope, and an environment-wide
    connection never on an org removal. Removing a user from one org they share with
    another org on the same connection previously deactivated — or with the `Delete`
    policy, **DELETED** — a user still entitled through the other org.
  - **409 reconcile no longer trusts a filter-ignoring peer.** `findByExternalId`
    adopts a remote record only when the response is unambiguous AND the matched
    resource actually carries the requested `externalId`
    (`ScimResult::resourceIdForExternalId()`). A downstream SCIM server that ignores
    the `externalId eq` filter and returns its whole list can no longer bind an
    arbitrary remote user as this subject's mirror (then wrongly PATCH/DELETE it).
  - **OAuth token cache now expires.** The client-credentials token is cached with
    its `expires_in` lifetime (minus a skew margin) and refreshed on expiry, so the
    singleton client in a long-running worker no longer serves a dead token and
    dead-letters every operation after the first expiry.

## [0.9.0] - 2026-07-15

### Added

- **SIEM audit streaming (`src/AuditStreaming/`).** A thin, isolation-critical
  binding that mirrors the hash-chained, environment-scoped audit trail OUT to a
  customer's SIEM (Splunk HEC, Elastic ECS, Graylog GELF, ArcSight/CEF, generic
  JSON). It composes two new runtime dependencies rather than reimplementing
  delivery: `cboxdk/siem` (the `SiemEvent` value object + formatters) and
  `cboxdk/laravel-siem` (the transactional-outbox delivery engine: batching, retry /
  dead-letter / circuit-breaker, SSRF-guarded HTTP egress, encrypted secrets,
  redaction).
  - **Environment-owned models (`Models\AuditStream`, `Models\AuditStreamDelivery`).**
    Subclasses of the engine's `LogStream` / `StreamDelivery` with
    `BelongsToEnvironment`. Pointed at by `config('siem.models.*')`, so the engine's
    registry, dispatcher and pump inherit the hard environment scope for free —
    deny-by-default, no bespoke tenancy checks. A migration adds an indexed
    `environment_id` to the engine's `log_streams` and `stream_deliveries` tables
    (runs after the engine's own create migration).
  - **`StreamingAuditLog` decorator (behavior addition).** Bound via
    `app->extend(AuditLog::class, …)`, so it composes with a host decorator (e.g.
    impersonation attribution — stamped `context.impersonated_by` flows to the SIEM
    automatically). On `record()` it maps the `AuditEntry` to a `SiemEvent` and writes
    the outbox row **in the same database transaction as the entry** (transactional
    outbox → at-least-once; a rolled-back caller leaves neither the entry nor an
    orphan delivery). Deny-by-default: with no stream configured in the environment it
    is a no-op beyond the inner `record()`. `verifyChain()` / `checkpoint()` delegate
    unchanged.
  - **`Contracts\SiemEventMapper` + `DefaultSiemEventMapper` (new contract).** Maps
    `AuditEntry` → `SiemEvent`; rebind to refine category/outcome/severity. Two
    invariants are fixed by contract: the event **id is the entry hash** (dedup /
    idempotency key), and the context carries `sequence`, `hash`, `prev_hash` and
    `organization_id` so the receiving SIEM can verify chain continuity and detect
    gaps/reorder/replay.
  - **Async pump with environment reconstruction.** `Jobs\PumpAuditStream`
    (`ShouldBeUnique` per stream) resolves the stream's `environment_id` via a
    provisioning-only `EnvironmentContext::withoutScope()` read, then runs the engine's
    delivery inside `EnvironmentContext::runAs($env, …)` so the hard scope matches and
    only that environment's rows are ever loaded. `Console\PumpAuditStreamsCommand`
    (scheduled every minute, mirroring the Webhooks module) is the single
    cross-environment step: under `withoutScope` it enumerates enabled streams across
    all environments and dispatches one pump each — it dispatches, it never delivers.
  - **Config.** New `cbox-id.audit_streaming.schedule` toggle. The provider forces
    three engine keys: `siem.models.log_stream`, `siem.models.stream_delivery`, and
    `siem.schedule.enabled = false` (laravel-id owns scheduling so the pump can
    reconstruct each stream's environment).
  - **Testing.** `Testing\InteractsWithAuditStreaming` (env-aware stream registration,
    an in-memory fake sink, synchronous pump) — dogfooded by the suite.

### Security

- **Environment isolation for streaming is structural, proven at both stages.** An
  env-A audit entry only ever matches/writes env-A streams (dispatch), and the pump
  for an env-A stream can only load/deliver env-A rows (pump) — enforced by the
  env-owned models and the hard scope, not a filter. Covered by cross-environment
  tests at both stages.
- **`siem.http.verify_url` (SSRF guard) and `siem.http.tls_verify` are operator-only.**
  Documented (config + `docs/security/audit-streaming.md`) as deployment-level toggles
  that must NEVER be exposed to a tenant/org admin — a tenant able to disable the SSRF
  guard could turn a stream into an SSRF primitive against internal infrastructure.

### Dependencies

- Added runtime deps `cboxdk/laravel-siem` (`^0.1`) and `cboxdk/siem` (`^0.1`), both
  MIT, resolved from Packagist. SBOM regenerated (78 → 80 components).

## [0.8.0] - 2026-07-15

### Added

- **Bulk user import + lazy password-hash migration (`src/Identity/`).** The
  enterprise migration wedge: import users from another provider
  (Auth0/Cognito/Firebase/a CSV) INCLUDING their existing password hashes, so they
  sign in on day one, with each foreign hash transparently upgraded to the platform
  hasher (argon2id) on first successful login — no forced reset, no dual-run window.
  - **Multi-algorithm hash verification (`Identity\Hashing`).** New contract
    `Identity\Contracts\HashVerifier` (`supports`/`verify`/`needsRehash`) with
    `NativePasswordVerifier` (bcrypt `$2y$/$2a$/$2b$` + argon2 `$argon2i$/$argon2id$`
    via PHP's vetted `password_verify`/`password_needs_rehash` — nothing hand-rolled)
    and a **deny-by-default** `HashVerifierRegistry` bound to the contract: a hash no
    registered verifier `supports()` fails `verify()` — never a silent pass. The
    registry is the seam a host uses to add a foreign format (Firebase scrypt,
    PBKDF2, `{SSHA}`) by wrapping a vetted library, via
    `config('cbox-id.hashing.verifiers')`.
  - **Lazy migration in `DatabaseSubjects::verifyPassword()`.** Verification now
    routes through the registry; on a correct password against a foreign/legacy hash
    (or the platform algorithm with weaker-than-current parameters) the plaintext is
    re-hashed with the platform hasher and persisted in place. The constant-time
    dummy-verify (no enumeration/timing oracle) and active-status gating are
    preserved.
  - **Import service.** New contracts `Identity\Contracts\UserImport` +
    `DatabaseUserImport`, value objects `ImportedUser` / `ImportOptions` /
    `ImportResult` / `ImportError`. Idempotent per email (skip or `upsert`), batched
    in a transaction per chunk with atomic rows, per-row errors collected instead of
    aborting the run, and **deny-by-default** on credentials — with
    `ImportOptions::$rejectUnverifiableHashes` (default) a `passwordHash` no verifier
    supports is a per-row error, so you can't import a user who could never log in.
    Attaches each user to an organization via `Organization\Contracts\Memberships`
    and honors the per-row verified-email flag.
  - **Artisan `cbox-id:users:import {file} {--org=} {--format=csv|json} {--upsert}
    {--role=}`** — streams a CSV/JSON export into the importer and exits non-zero if
    any row errored.
  - **Contract change:** `Identity\Contracts\Subjects` gains `storeCredential()`
    (store an already-hashed credential verbatim, for import/migration — NOT
    re-hashed, upgraded lazily on next login). Hosts with a custom `Subjects`
    resolver must implement it.
  - `Testing\InteractsWithImport` helper. Docs: cookbook recipe *Migrate users from
    another provider* and extension-points *Custom hash verifiers*.
  - **Environment integrity on the import command.** `cbox-id:users:import` always
    provisions into the TARGET ORG's own environment: when an environment is already
    ambient it must be the org's (a mismatch is refused, never a silent import into
    the wrong plane), and a bare console invocation pins it from the org. The
    `--upsert` match is by environment-wide email (a user is unique per
    `(environment, email)` and may belong to several orgs) — the recipe documents
    why this stays an operator-run console command with no per-org authorization.

## [0.7.0] - 2026-07-15

### Added

- **SAML 2.0 Identity Provider (`src/SamlIdp/`).** Cbox ID can now act as the SAML
  IdP that downstream service providers (Salesforce, Workday, AWS, any SP) federate
  to — the mirror of the existing relying-party side. New contracts
  `SamlIdp\Contracts\{SamlIdentityProvider, ServiceProviders, IdpKeyMaterial}`:
  - **Registered SPs** (`saml_service_providers`, environment-owned `ServiceProvider`
    model): `entity_id` (unique per environment), an exact-match `acs_url` (the only
    place an assertion is ever sent), `name_id_format`/`name_id_attribute`,
    `attribute_mappings`, the SP `certificate`, and `want_authn_requests_signed`.
  - **`parseAuthnRequest()`** decodes the request (base64 + DEFLATE for redirect,
    base64 for POST) through an XXE-safe loader and validates deny-by-default: the
    issuer must be a registered, active SP; a request-supplied
    `AssertionConsumerServiceURL` must equal the registered ACS exactly
    (open-redirect defense); when signing is required the signature must verify
    against the SP certificate with the algorithm **pinned to RSA-SHA256** (SHA-1 and
    unknown algorithms refused).
  - **`issueResponse()`** mints a signed SAML Response containing a signed Assertion:
    bearer `SubjectConfirmation` (Recipient = registered ACS, `InResponseTo`, short
    `NotOnOrAfter`), `Conditions` with a ~5-minute window and an `AudienceRestriction`
    pinned to the SP EntityID, an `AuthnStatement`, and an `AttributeStatement` from
    the SP's mappings. The Assertion is signed with `robrichards/xmlseclibs`
    (enveloped signature, **exclusive C14N**, **RSA-SHA256**, SHA-256 digest) and the
    Response with `onelogin/php-saml`'s `addSign`. XML is built with DOM so every
    value is escaped. SHA-1 is never emitted.
  - **One identity:** the IdP signs with the platform's active RSA signing key
    (`KeyManager::activeSigningKey`), the same key behind JWKS/OIDC — no second key
    store. The public half is published as a self-signed X.509 certificate, persisted
    per `kid` (`saml_idp_certificates`).
  - **Endpoints** (behind `ResolveEnvironment` + throttle): `GET /sso/saml/idp/metadata`,
    `GET|POST /sso/saml/idp/sso` (parse + validate + host hand-off + auto-POST form),
    `GET|POST /sso/saml/idp/slo` (local session termination). Thin controllers — the
    authenticate-the-subject step is the host's, as with OAuth `/authorize`.
  - **Testing:** `Testing\InteractsWithSamlIdp` trait (now with `samlSigningKeypair()`
    and `makeSignedPostAuthnRequest()` helpers) + `FakeServiceProviders`. The suite
    proves issued assertions against `onelogin/php-saml` acting as the SP (signature,
    audience, recipient, `InResponseTo`, conditions), asserts a tampered assertion is
    rejected by that verifier, and covers the ACS-mismatch, unregistered-SP, XXE, and
    algorithm-pin refusals — plus the POST-binding signed-request path (accepted valid;
    refused when unsigned, tampered, SHA-1, or XML-Signature-Wrapped).
  - **Integrating (host apps):** the HTTP-POST binding is a cross-site form POST with
    no Laravel CSRF token, so hosts must add `sso/saml/idp/sso` to
    `VerifyCsrfToken::$except` (fail-closed — a missing exemption breaks the POST
    binding, it does not weaken security). See `docs/core-concepts/saml-idp.md`.
  - **Not yet implemented (honest scope):** assertion **encryption**
    (`EncryptedAssertion`), full Single Logout fan-out / signed `LogoutResponse`, and
    IdP-initiated (unsolicited) SSO. See `docs/core-concepts/saml-idp.md`.

### Security

- **SAML IdP — XML Signature Wrapping (XSW) hardening on the POST-binding
  signed-`AuthnRequest` path (defense-in-depth).** `onelogin/php-saml`'s
  `Utils::validateSign()` confirms *a* signature verifies against the SP certificate
  but does not bind the signed element to the request root the parser reads. The
  embedded-signature verification now, before trusting the result, requires the
  message `ds:Signature` to be a single enveloped signature that is a **direct child
  of the `AuthnRequest` root**, requires its `Reference` to **cover that root** (empty
  URI = whole document, or `#<root ID>` — never a wrapped or duplicated element), and
  **pins verification to that exact signature** (via `validateSign`'s `$xpath`) so the
  verified crypto is the one enveloped in the root rather than whichever `ds:Signature`
  appears first in document order. The embedded `SignatureMethod`/`DigestMethod` are
  also pinned to **RSA-SHA256 / SHA-256** (onelogin would otherwise accept SHA-1),
  matching the redirect binding. Impact of the prior gap was bounded — a forged
  request still only produced an assertion delivered to the genuine registered ACS —
  so this is hardening, not a fix for a known exploit. Covered by a new XSW regression
  test.

## [0.6.0] - 2026-07-14

### Added

- **DNS domain verification + home-realm discovery.** New `Federation\Contracts\DomainVerification`
  (`DatabaseDomainVerification`): an organization registers an email domain, proves
  control by publishing a DNS TXT challenge at `_cbox-id-challenge.<domain>`, and
  once verified, `connectionForEmail($email)` routes matching users to the org's
  active SSO connection. Resolution is deny-by-default — an unverified domain never
  routes and never captures — and environment-scoped, so a domain verified in one
  environment never routes a login in another. New `verified_domains` table +
  `VerifiedDomain` model.
- **Optional capture gate.** A verified domain carries a `capture` flag: off by
  default (verification enables routing only); when the host turns it on, matching
  users are meant to be forced into the org's auth policy. The package exposes the
  flag; enforcement is the host's.
- **`DnsResolver` contract** (`SystemDnsResolver` default over `dns_get_record`) so
  the DNS lookup is swappable — a host can bind a direct-authoritative resolver to
  avoid recursive-cache staleness at verification time — and testable
  (`Testing\FakeDnsResolver`, plus `InteractsWithFederation::fakeDns()` /
  `makeVerifiedDomain()`). The library ships only the dependency-light default.

## [0.5.0] - 2026-07-14

A follow-up hardening + DX pass from a deep review, plus operator MFA and
contract-level suspension.

### Security

- **Outbound OIDC token exchange is now SSRF-guarded.** `OidcClient::exchangeCode()`
  POSTed to an org-admin-configured `token_endpoint` without the SSRF guard the
  webhook path already used, so a malicious endpoint (e.g. cloud metadata at
  `169.254.169.254`) was reachable server-side. It now runs through
  `SafeFederationUrl` — the same `cboxdk/laravel-ssrf` `UrlGuard` as webhooks,
  with DNS-pinned options (no TOCTOU) and a `cbox-id.federation.verify_url`
  toggle for on-prem internal IdPs.
- **Social identity linking race closed.** `DatabaseSubjects::link()` was
  check-then-insert with no lock, and the `identities` uniqueness index didn't
  bite for connection-less (social) links because SQL treats NULL `connection_id`
  as distinct. `link()` now serializes under `lockForUpdate` in a transaction, so
  a concurrent double-link yields one row.

### Added

- **`client_secret_basic` at the token endpoint** (RFC 6749 §2.3.1). `/oauth/token`
  accepted client credentials only in the body while discovery advertised Basic,
  so Basic-defaulting clients got `invalid_client`. A shared `ClientAuthenticator`
  now reads Basic-first then body, rejects combining both, and is used by the
  token, introspection, revocation, and PAR endpoints (previously four divergent
  copies).
- **Database-backed default environment.** New `environments.is_default` column,
  `Environment::makeDefault()`, and `EnvironmentResolver::defaultEnvironment()`.
  The single-tenant / host-less fallback plane is now the row flagged in the
  database rather than an env var written to `.env`, so a horizontally-scaled,
  stateless deployment (k8s, no writable `.env`) resolves the same default across
  every replica. `cbox-id.environments.default` config remains an explicit
  override that wins when set.
- **`cbox-id:install` bootstraps the first environment.** It now creates (or
  reuses) an environment, marks it the default, and mints the first signing key
  *inside that environment's scope* — fixing the fresh-install failure where the
  deny-by-default scope left the signing-key step (and every first query) hitting
  an empty scope.
- **Optional `base64:` prefix on `CBOX_ID_CRYPTO_KEY`.** `CryptoServiceProvider`
  strips a leading `base64:` (Laravel's conventional prefix) before decoding, so
  a key copied with the prefix no longer throws at boot.
- **`cbox-id.oauth.authorization_endpoint` config** (env `CBOX_ID_AUTHORIZATION_ENDPOINT`).
- **Operator MFA.** New `Platform\Contracts\OperatorMfa` + `DatabaseOperatorMfa`:
  TOTP enrolment/verification and single-use recovery codes for platform
  operators, so the control-plane root account can require a second factor. It is
  a SEPARATE subsystem keyed by operator id on non-environment-owned tables
  (`operator_mfa_factors`, `operator_mfa_recovery_codes`) — an operator's factor
  is never a tenant user's. It shares the vetted RFC 6238 `TotpAuthenticator`,
  the `SecretBox` at-rest sealing, and recovery-code formatting with subject MFA.
- **Suspension through contracts, with audit.** `Organizations::suspend()` /
  `reactivate()` and `PlatformOperators::suspend()` / `reactivate()` transition
  status *and* record an audit event (`ActorType::Operator`), so a suspension is
  attributable instead of a silent `->update()`. The operator variant refuses to
  suspend the last active operator (`CannotSuspendLastOperator`) — no lock-out.

### Changed

- **`organizations.slug` uniqueness is environment-scoped** (`unique(['environment_id','slug'])`).
  It was globally unique, contradicting the hard-boundary model — two environments
  could not both have an `acme` org, and the collision surfaced as a raw
  `QueryException` instead of `SlugAlreadyTaken`.
- **SCIM controllers are thin again.** `Scim\UserController` / `Scim\GroupController`
  no longer query models or implement PATCH/filter/membership logic inline; that
  moved behind new `DirectoryUsers` / `DirectoryGroups` contracts. SCIM wire
  behaviour is unchanged.
- **Discovery no longer advertises an unserved `authorization_endpoint`.**
  `ServerMetadata` omits the key unless `cbox-id.oauth.authorization_endpoint` is
  set (interactive authorize is the host app's responsibility).
- **`TotpAuthenticator` and `TotpEnrollment` moved to `Kernel\Crypto`** (from
  `Identity\Mfa` / `Identity\ValueObjects`). TOTP is a shared crypto primitive;
  the move lets Platform's operator MFA reuse it without a Platform→Identity
  dependency. Recovery-code formatting extracted to a shared
  `Kernel\Crypto\Concerns\FormatsRecoveryCodes` trait. `ActorType` gains
  `Operator`.

### Breaking

- `EnvironmentResolver` gains `defaultEnvironment(): ?Environment` — custom
  implementations of the contract must add it.
- `Organizations` gains `suspend()` / `reactivate()`, and `PlatformOperators`
  gains `suspend()` / `reactivate()` — custom implementations must add them.
- `TotpAuthenticator` / `TotpEnrollment` moved namespace (`Identity\Mfa` /
  `Identity\ValueObjects` → `Kernel\Crypto` / `Kernel\Crypto\ValueObjects`);
  update imports.
- The `organizations` unique index changed (fresh-install migration edit, in
  keeping with the 0.x dogfooding cadence — no `alter` shipped).

## [0.4.0] - 2026-07-13

A security-hardening pass from a full review. Isolation is now enforced by the
deny-by-default global scope across every tenant table rather than by per-query
discipline. Breaking: adds `environment_id` to several tables (schema change).

### Security

- **Environment isolation is now defense-in-depth.** `WebhookEndpoint` +
  `WebhookDelivery` were not environment-owned — a platform-wide (null-org)
  endpoint received *every* environment's events (cross-environment payload
  leak). Both are now environment-owned, and 13 more tenant-relevant tables
  gained the global scope (`DirectoryUser/Group`, `WebAuthnCredential`,
  `MfaFactor`, `MfaRecoveryCode`, `MagicLinkToken`, `PasswordResetToken`,
  `EmailVerificationToken`, `AccessToken`, `ServiceAccount`,
  `PushedAuthorizationRequest`, `Role`, `RoleAssignment`, `SamlAuthRequest`), so
  a query that forgets its filter can no longer cross environments. Replay tables
  (`DpopProof`, consumed SAML assertions) and the shared permission catalog stay
  global by design.
- **Device-grant redemption** flips `approved → redeemed` under `lockForUpdate`
  in a transaction, closing a single-use TOCTOU for a shared/logged `device_code`.
- **SAML Single Logout** scopes its identity lookup by `connection_id` (as login
  does), so a signed `LogoutRequest` from one connection can't force-logout a user
  belonging to another.
- **Magic-link redemption** locks the token row.
- **Credential checks** run a constant-cost dummy verify on the miss path
  (`Subjects`, `PlatformOperators`) — no username-enumeration timing oracle.
- **Host-based environment resolution** only trusts a leading subdomain label
  under a configured `cbox-id.environments.base_domains`; a spoofed `Host` can no
  longer select a plane.
- **Tenancy context managers** are `scoped`, not `singleton`, so a killed
  Octane worker can't leak a suspension counter across requests and collapse
  scoping.
- The configured `cbox-id.models.user` **must extend the package `User`** (which
  carries `BelongsToEnvironment`), so a host override can't silently unscope the
  users table.

### DX

- Docs: the flagship examples referenced a non-existent `UserDirectory` contract
  — renamed to `Subjects`/`DatabaseSubjects` across the README and docs so they
  run as written.
- Added `Platform/Testing/InteractsWithPlatform` (`makeOperator()`), dogfooded in
  the Platform tests, and a `Kernel/Crypto/Testing/FakeSecretBox` so hosts can
  test secret-sealing without libsodium.
- `@throws` tags on `Subjects` and `DeviceAuthorization`.

## [0.3.2] - 2026-07-13

### Fixed

- **`OrganizationHierarchy::move()` now syncs the `parent_id` column.** 0.3.1
  rewrote only the closure table, leaving the denormalized direct-parent column
  stale — so tree views built from `parent_id` didn't reflect a move. `move()`
  now updates both representations atomically.

## [0.3.1] - 2026-07-13

### Added

- **`OrganizationHierarchy::move()`** — reparent an existing organization, with
  its whole subtree, under a new parent (or promote to root). Rewrites the
  closure table correctly at any depth and throws `CannotReparent` if the target
  is the node itself or one of its descendants (cycle guard). Fills the gap that
  `attach()` — create-time only — left for tenant hierarchy management (moving a
  customer between resellers, restructuring OUs).

## [0.3.0] - 2026-07-13

Adds **platform operators** — the identity above every environment (the WorkOS
"team member" / developer account). Operators authenticate once at the platform
level and can then assume any environment's console, without needing an account
inside each plane.

### Added

- **Platform operators.** A new `platform_operators` table and
  `Cbox\Id\Platform\Contracts\PlatformOperators` repository. Operators are *not*
  environment-owned — no `environment_id`, globally unique email — so they resolve
  identically from any environment (asserted in the `@group isolation` suite).
  Password verification is gated on active status. `PlatformServiceProvider` binds
  the repository; a new migration ships the table.
- **Docs.** `core-concepts/platform-operators.md` — the model, the WorkOS/Auth0/
  Okta mapping, provisioning, and the isolation guarantee.

### Fixed

- **`User` now hashes assigned passwords.** The model gained a `password => hashed`
  cast, so a raw `User::create(['password' => ...])` (seeders, factories) hashes
  with the configured driver instead of storing plaintext — which previously threw
  `This password does not use the Argon2id algorithm` at sign-in. The `Subjects`
  API, which hashes up front, is unaffected (the cast skips already-hashed values).

## [0.2.0] - 2026-07-13

Adds **environments** — the hard identity boundary above organizations
(staging/prod, per-product and white-label isolation), WorkOS-style. This is a
breaking change: the schema and query scoping change platform-wide.

### Added

- **Environments.** A first-class isolation layer above the organization tenant:
  its own user pool, signing keys, issuer and organization tree. Resolved per
  request from the host (`ResolveEnvironment` middleware + `EnvironmentResolver`;
  custom-domain or leading-subdomain-as-slug). See
  [Environments & the isolation model](core-concepts/environments.md).
- `Environment` model + `environments` table; `EnvironmentContext`,
  `EnvironmentScope`, `BelongsToEnvironment`, `EnvironmentOwned`,
  `GenericEnvironment`; `actingAsEnvironment*` test helpers.
- A dedicated cross-layer isolation suite (`--group=isolation`) proving the
  boundary across tenancy, crypto, identity and the OAuth surface.

### Changed (breaking)

- Every environment-owned model now carries `environment_id` and is scoped by a
  **deny-by-default** environment scope, independent of (and harder than) the
  organization scope: `withoutScope`/roll-up on the org dimension never crosses an
  environment.
- **User email uniqueness is now per environment** (`(environment_id, email)`),
  and federated-link uniqueness includes the environment — the same email is a
  distinct user across environments.
- **Signing keys, JWKS and the issuer are per environment** — a token signed in
  one environment never verifies in another.
- API requests must resolve an environment from the host. Set
  `cbox-id.environments.default` for single-tenant/on-prem; a multi-tenant
  deployment refuses an unknown host.

## [0.1.2] - 2026-07-13

### Fixed

- Accept the canonical single-slash private-use redirect URI form
  (`com.example.app:/cb`) at registration, so native mobile apps (RFC 8252 /
  AppAuth) register cleanly.

## [0.1.1] - 2026-07-13

### Security

- Hardening pass: SAML `InResponseTo` enforcement, DPoP enforced at the resource
  surface and bound to refresh tokens, account-status gating across all login
  paths, step-up on MFA enrollment / provider unlink, webhook DNS pinning +
  dead-lettering, admin-only console reads, and per-client token ownership on
  introspection/revocation.

### Changed

- Documentation restructured into the topic-folder layout.

## [0.1.0] - 2026-07-13

First tagged release. Pre-1.0: the public API may still change between `0.x`
releases, and only the latest `0.x` tag is supported.

### Added

- **OAuth 2.0 / OIDC authorization server** — `authorization_code` with mandatory
  PKCE (S256), `client_credentials`, refresh tokens with rotation + reuse
  detection (family revocation), and the Device Authorization Grant (RFC 8628).
- **Sender-constrained tokens (DPoP, RFC 9449)** — proof validation at the token
  endpoint, enforcement at the resource surface (`cnf.jkt` + `ath`), and DPoP-key
  binding of refresh tokens.
- **Pushed Authorization Requests** (RFC 9126) and a **FAPI 2.0 baseline** profile.
- **Token endpoint hardening** — `at+jwt` access tokens (RFC 9068), RFC 8707
  resource indicators with `invalid_target` rejection of malformed values, and
  the RFC 9207 `iss` authorization-response parameter.
- **Introspection (RFC 7662) and revocation (RFC 7009)** with per-client token
  ownership enforcement.
- **Discovery** — Authorization Server Metadata (RFC 8414), Protected Resource
  Metadata (RFC 9728), Dynamic Client Registration (RFC 7591/7592), and JWKS.
- **Token signing** — RS256, ES256 and EdDSA (Ed25519, RFC 8037) with `kid`-overlap
  key rotation.
- **UserInfo** endpoint and `id_token` claims (`at_hash`, `auth_time`, `acr`, `amr`,
  `nonce`).
- **Federation** — SAML 2.0 SP (metadata, SP-initiated login, SLO, InResponseTo
  enforcement) and OIDC as a relying party (with `nonce`).
- **Directory sync (SCIM 2.0)** — Users, Groups + membership, the Enterprise User
  extension, and PATCH (including `remove`); deprovisioning deactivates the
  account and revokes sessions.
- **Identity** — sessions with idle + absolute timeout and step-up, password auth,
  MFA (TOTP, recovery codes, WebAuthn/passkeys with user-verification), magic
  links, password reset, email verification, and account-status gating.
- **Organizations & tenancy** — deny-by-default tenant isolation, memberships with
  last-owner protection, and a closure-tree hierarchy.
- **Authorization** — a policy decision point, ReBAC relationship store, and
  entitlements as capability gates (hybrid token-claim / decision-endpoint model).
- **Webhooks** — HMAC-signed delivery with SSRF-guarded, DNS-pinned requests,
  bounded retries with dead-lettering, and a scheduled retry sweep.
- **Audit** — an append-only, hash-chained trail with signed checkpoints.

### Security

- Fixed a cross-tenant account-takeover vector in federated identity linking:
  SSO connection identities are now namespaced to their connection.
- Enforced SAML `InResponseTo` against a request store, DPoP at the resource
  surface and on refresh tokens, account-status gating across all login paths,
  step-up on MFA enrollment and provider unlink, and admin-only reads on the
  console. See the security advisories for detail.
