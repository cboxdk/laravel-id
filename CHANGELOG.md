# Changelog

All notable changes to `cboxdk/laravel-id` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Confirmed security vulnerabilities and their fixes are cross-referenced under
**Security** below and in the repository's security advisories.

## [0.49.0] - 2026-07-24

Platform-review remediation. Every finding was adversarially verified before it was
fixed; the SSRF-redirect and PAR-under-validation reports were refuted and dropped.

### Security

- **Refresh-token rotation is now idempotent within the reuse-grace window.** A replayed
  token in the window returned a second, independent live token; it now returns the same
  successor, so a stolen token cannot be laundered into its own lineage. Reuse detection
  past the window (whole-family revocation) is unchanged. Adds an encrypted
  `successor_token` column (additive migration).
- **Token exchange requires proof-of-possession for sender-constrained tokens (RFC 9449).**
  A DPoP-bound subject token can no longer be exchanged without a DPoP proof matching its
  `cnf.jkt`; the issued token inherits the binding.
- **OIDC federation enforces `azp` on multi-audience id_tokens (OIDC Core §3.1.3.7).** A
  token naming more than one audience is rejected unless it carries an `azp` equal to the
  configured client id.
- **Permission catalog is environment-scoped.** App-declared permissions carry an
  `environment_id` (backfilled from the declaring client) and are visible only within
  their environment; manual permissions remain platform-global. Closes a cross-environment
  read/bind of another tenant's declared permission keys. (Additive migration.)
- **Passkey registration rejects credential reassignment** (WebAuthn §7.1 step 22), and the
  signature-counter check is now atomic under a row lock (no concurrent same-counter pass).
- **Device authorization authenticates confidential clients** (RFC 8628) via the shared
  client authenticator, closing prompt-spam under a confidential client's identity.

### Fixed

- **Discovery advertises only what it serves:** `id_token_signing_alg_values_supported` is
  derived from the live JWKS (RS256 only, not an aspirational superset), and `fragment` is
  dropped from `response_modes_supported`.
- **CIBA binds the id_token to the request `nonce`** (previously dropped).
- **SCIM Group PATCH/PUT reject invalid operations** (RFC 7644): unknown op/path return a
  `invalidSyntax`/`invalidPath` SCIM error instead of a silent 200, and full PUT requires
  `displayName`.

### Changed

- **Usage kernel depends on a `ReconcilableScopes` contract** instead of importing the
  Organization domain model (kernel→domain dependency reversal removed).
- **Environment status is typed** with the new `EnvironmentStatus` enum.
- **`final` removed from value objects** — the library must not seal classes host code may
  extend.

## [0.15.0] - 2026-07-15

### Added

- **External actions / inline hooks (`src/ExternalActions/`).** Synchronous extension
  points where the platform consults registered logic that can ENRICH or VETO an
  operation — the Okta-inline-hook / Auth0-Actions capability. Distinct from webhooks
  (which only notify, async): a hook participates in-band and changes the outcome. No new
  runtime dependency (reuses the crypto SecretBox, the already-present
  `cboxdk/laravel-ssrf` guard, the audit trail and the environment scope).
  - **`Contracts\ActionPipeline` + `DefaultActionPipeline` (new contract).** For a hook
    point, runs the in-process actions then the external endpoints and folds the results:
    the first deny short-circuits (vetoes the operation); enrichment is merged (later
    wins). A hook point with no actions is a cheap allow, so callers invoke it
    unconditionally on the hot path.
  - **In-process actions (`Contracts\Action` + `ConfigActionRegistry`).** A host class
    that runs synchronously at a hook point, returning `ActionResult::continue([...])` or
    `deny($reason)`. Deny-by-default: only classes listed in
    `cbox-id.external_actions.hooks.<point>` run.
  - **External HTTP actions (`Contracts\ExternalActions` + `HttpActionTransport`).**
    Register a customer HTTPS endpoint; the platform POSTs a SIGNED
    (HMAC-SHA256 over `"{ts}.{body}"`, `X-Cbox-Signature`), SSRF-GUARDED (URL asserted at
    registration, IPs pinned per send, redirects off, TLS on), SHORT-TIMEOUT, NO-RETRY
    request and interprets `{"action":"continue"|"deny","claims":{…},"reason":"…"}`. The
    per-endpoint signing secret is reveal-once and sealed at rest.
  - **Fail-closed by default.** A hook that throws / times out / errors / returns non-2xx
    DENIES the operation (a security control that fails open is not a control). Config
    `external_actions.fail_open` trades that for availability on enrichment-only hooks.
  - **Flagship wiring — the `TokenMinting` hook in `JwtTokenIssuer`.** Runs just before an
    access token is signed, on every grant (client-credentials, authorization-code,
    refresh, device, CIBA). An action can add claims (reserved protocol/security claims —
    `iss`/`sub`/`exp`/`scope`/`aud`/`cnf`/`ent`/… — can never be overwritten) or veto
    issuance (`ActionDenied`, mapped by the token endpoint to `access_denied`) BEFORE the
    `jti` row is written, so a denied token leaves no trace.
  - **Models + config + testing.** Env-owned `ExternalActionEndpoint` (migration
    `external_action_endpoints`); config `cbox-id.external_actions.*` (verify_url, timeout,
    connect_timeout, fail_open, hooks map); `Testing\InteractsWithExternalActions` +
    `Testing\FakeActionTransport` (network-free), dogfooded by 17 tests (enrichment,
    reserved-claim protection, veto→no-jti + `access_denied`, fail-closed/open, SSRF
    refusal, sealed-secret at rest, environment isolation, HTTP sign/interpret).

### Security

- Inline hooks fail CLOSED, veto before any token row is written, cannot overwrite reserved
  claims, and make signed, SSRF-guarded, no-redirect egress calls. See
  [security/external-actions.md](docs/security/external-actions.md).

## [0.14.0] - 2026-07-15

### Added

- **`DeviceAuthorization::pending()` (device flow consent lookup).** A read method on
  the existing device-grant contract that resolves a live (pending, unexpired) request
  by its `user_code`, returning a new `PendingDeviceAuthorization` value object
  (`clientId`, `scopes`, `expiresAt`). This lets a verification/consent screen show
  **which** client and scopes are asking BEFORE the user approves — the piece a
  deployable app needs to build the RFC 8628 "enter the code on your TV/CLI" screen. It
  returns null for an unknown, expired or already-decided code and never exposes the
  `device_code` (the requesting device's polling secret). Additive; the rest of the
  device grant is unchanged.

## [0.13.0] - 2026-07-15

### Added

- **Access governance — IGA (`src/Governance/`).** The Identity Governance &
  Administration layer over the platform's RBAC roles and organization memberships:
  periodic access reviews and Segregation-of-Duties policies. No new runtime dependency
  — it composes the existing `Roles`, `Memberships`, audit and events, all
  environment-owned and deny-by-default.
  - **`Contracts\AccessReviews` + `DatabaseAccessReviews` (new contract).** `open()`
    snapshots every DIRECT role assignment and membership in an organization as pending
    certification items; `certify()`/`revoke()` record a reviewer's decision (reversible
    while the campaign is open); `close()` **applies** every revoke against the real
    contracts (`Roles::unassign()` / `Memberships::remove()`) and marks the campaign
    closed. Items left un-reviewed at close follow the campaign's `PendingPolicy`
    (default **Revoke** — unattested access is removed). A revoke the domain refuses
    (removing an org's last owner) is recorded un-applied with the reason and audited
    (`governance.access.revoke_blocked`), never silently dropped.
  - **`Contracts\SegregationOfDuties` + `DatabaseSegregationOfDuties` (new contract).**
    Policies over a mutually-exclusive set of roles. `evaluate()` returns a reasoned
    `Decision` (the authorization kernel's value object; deny carries `sod:{policyId}`)
    as a pre-grant gate the host calls before assigning a role; `wouldViolate()` is the
    boolean convenience; `violationsFor()` / `scan()` detect conflicts that already
    exist. Policies scope to one org or environment-wide (`organizationId: null`).
  - **Scheduled auto-close.** `cbox-id:governance:close-overdue` (registered + scheduled
    every minute, config-gated by `cbox-id.governance.schedule`) closes any open campaign
    past its `due_at`, reconstructing each campaign's environment first
    (`withoutScope` → `runAs`).
  - **Additive read methods on `Roles`.** `assignmentsForSubject()` and
    `assignmentsInOrganization()` were added to the `AccessControl\Contracts\Roles`
    contract (and `RoleService`) so governance enumerates real grants through the
    contract rather than the model.
  - **Models.** `CertificationCampaign`, `CertificationItem`, `SodPolicy` — all
    `BelongsToEnvironment`. Migration adds `governance_campaigns`,
    `governance_certification_items`, `governance_sod_policies`.
  - **Config.** New `cbox-id.governance.schedule`.
  - **Testing.** `Testing\InteractsWithGovernance`, dogfooded by the suite (snapshot,
    apply-on-close, certified-survives, pending policies, last-owner block, closed-freeze,
    idempotent re-close, SoD gate + detection, environment isolation, scheduled close).

### Security

- Certification **applies** revokes against the real access contracts rather than
  recording paper decisions; un-reviewed items default to revoke; a refused revoke is
  surfaced and audited, never dropped; every decision and application is correlated by
  `campaign_id` on the hash-chained trail. See
  [security/governance.md](docs/security/governance.md).

## [0.12.1] - 2026-07-15

### Changed

- Add `keywords` to `composer.json` (identity, authentication, sso, saml, scim,
  oauth, oidc, rbac, audit) so the package is discoverable on Packagist and its
  GitHub topics are populated. Metadata only — no code changes.

## [0.12.0] - 2026-07-15

### Added

- **AI token vault (`src/TokenVault/`).** A deny-by-default broker for the downstream
  third-party credentials (OpenAI/GitHub/Google API keys and OAuth tokens) that
  autonomous / AI agents must present to the services they call. The agent never holds
  the long-lived secret; the vault does, sealed, and hands out short-lived audited
  leases. No new runtime dependency — it reuses the Crypto `SecretBox`, the hash-chained
  audit trail and the hard environment scope.
  - **`Contracts\SecretVault` + `DatabaseSecretVault` (new contract).** `store()` seals a
    credential via `SecretBox` (recoverable, AEAD-bound to the row — not a hash, because
    the vault must replay it); `grant()`/`revokeGrant()` are the deny-by-default
    authorization edge (a `client_id` → secret); `lease()` returns the plaintext to an
    authorized agent for immediate use with an advisory TTL; `rotate()`/`revoke()` are
    immediate. Every op is audited with actor + purpose, never the value.
  - **Uniform lease denial (no enumeration oracle).** Unknown secret, missing grant,
    revoked or expired all raise the same `LeaseDenied`; the real reason is written to
    the audit trail (`vault.lease.denied`), never returned. Management ops throw
    `SecretNotFound`.
  - **Environment-owned models (`Models\VaultSecret`, `Models\VaultGrant`).**
    `BelongsToEnvironment`; a `key_version` column makes a future manual master-key
    re-seal auditable (the crypto kernel has no master-key rotation). Migration adds
    `vault_secrets` + `vault_grants`.
  - **Config.** New `cbox-id.token_vault.default_lease_ttl_seconds` (the vault-wide lease
    ceiling; a per-grant `max_ttl_seconds` can only shorten it).
  - **Testing.** `Testing\InteractsWithTokenVault` + an in-memory `Testing\FakeTokenVault`
    that mirrors the deny-by-default semantics — dogfooded by the suite (lifecycle,
    grant-required + revoked/expired refusal, uniform denial, environment isolation,
    sealed-at-rest + AEAD context binding, value-absent-from-audit).
- **OpenID Connect CIBA — backchannel approval (`src/OAuthServer/`).** A new OAuth grant
  and endpoint for human-in-the-loop approval of agent actions, modelled on the device
  authorization grant. An agent starts a decoupled authentication naming the user; the
  user approves out-of-band; the agent polls for its tokens.
  - **`Contracts\BackchannelAuthentication` + `CibaAuthenticationService` (new contract).**
    `request()` resolves the user from `login_hint`, persists a pending request and emits
    `oauth.backchannel_authentication_requested` for the host to notify + drive its
    approval UI; `approve()`/`deny()` key off the INTERNAL request id (never the client's
    `auth_req_id`); `redeem()` is the poll grant. The `auth_req_id` is a CSPRNG secret
    stored only as a hash, single-use under a `lockForUpdate` mint, TTL-bounded and
    poll-throttled (`slow_down`) — the device grant's hardening, without a user_code.
  - **`POST /oauth/backchannel_authentication`** (client-authenticated) + the
    `urn:openid:params:grant-type:ciba` arm on `POST /oauth/token`, which returns an
    access token AND an id_token bound to the approving user (auth_time, nonce). Discovery
    advertises `backchannel_authentication_endpoint`,
    `backchannel_token_delivery_modes_supported: ["poll"]` and the grant type.
  - **Host boundary.** As with the OAuth consent screen, the user notification + approval
    surface is the host's; the package ships the protocol and emits the domain event.
    Poll mode only (ping/push not implemented).
  - **Config.** New `cbox-id.oauth.ciba.*`: `ttl_seconds` (approval window / ceiling on
    `requested_expiry`) and `poll_interval`.

### Security

- The token vault seals downstream credentials at rest and never returns which secret ids
  exist (uniform `LeaseDenied`); CIBA keeps the client's polling secret and the host's
  approval handle as separate identifiers so a client can never approve its own request.
  See [security/token-vault.md](docs/security/token-vault.md) and
  [security/ciba.md](docs/security/ciba.md).

## [0.11.0] - 2026-07-15

### Added

- **Delivered OTP channels (`src/Otp/`).** One-time passcodes over email / SMS as a
  verification and MFA factor, sitting alongside the existing authenticator-app TOTP,
  passkeys and magic links. A host wires it into its own step-up / second-factor /
  contact-verification flows — the module ships primitives, no UI. No new runtime
  dependency: it reuses the framework mailer (via the `Mailer` contract only), the
  crypto master key, Laravel's `RateLimiter`, the hash-chained audit trail and the
  hard environment scope.
  - **`Contracts\OtpService` + `DatabaseOtpService` (new contract).** `issue(purpose,
    recipient, channel, ip?)` generates a CSPRNG numeric code (`random_int`,
    configurable length, default 6), stores only its hash with a short TTL (default
    5 min), delivers the plaintext via the channel, and returns an `OtpChallenge`
    value object that never carries the code. `verify(challengeId, code, ip?)` /
    `verifyLatest(purpose, recipient, code, ip?)` are constant-time, single-use, and
    deny-by-default — unknown, expired, consumed, locked or wrong all fail with a
    uniform `OtpResult`, and the hash-compare runs on every path (a decoy on the miss)
    so there is no enumeration or timing oracle.
  - **`Contracts\OtpChannel` + `Contracts\OtpChannels` + `ChannelRegistry` (new
    contracts).** A deny-by-default sender registry: a channel key with no registered
    sender is refused (`UnknownOtpChannel`), never a silent no-op. Ships
    `EmailOtpChannel` (framework mailer, plain honest text), plus `LogOtpChannel` and
    `NullOtpChannel` for local dev / tests. **SMS is a CONTRACT ONLY** — a host
    registers its own `OtpChannel` wrapping its provider's SDK; this package ships no
    SMS SDK.
  - **`Contracts\OtpHasher` + `KeyedOtpHasher` (new contract).** A short numeric code
    has little entropy, so the at-rest value is a **keyed HMAC** under a key derived
    (HKDF) from the crypto master key — which lives outside the database — rather than
    a plain hash (offline-brute-forceable) or a slow password hash (a CPU-amplification
    lever on the verify path). All vetted PHP core primitives; nothing hand-rolled.
  - **Environment-owned model (`Models\OtpChallenge`).** `BelongsToEnvironment`, so a
    challenge issued in one environment is structurally invisible to any other. A
    migration adds the `otp_challenges` table (purpose, channel, recipient, code_hash,
    expires_at, attempts, max_attempts, consumed_at).
  - **Abuse resistance (layered).** Issuance is throttled both per recipient+purpose+IP
    **and** per recipient across all purposes/IPs — the second cap is what bounds
    bombing / SMS-cost abuse when an attacker rotates the purpose or source IP.
    Verification is throttled globally per IP **and**, on the `verifyLatest()` recipient
    path, per recipient+purpose across IPs. `verifyLatest()` targets only a LIVE,
    unlocked challenge (skipping expired/attempt-capped rows), so a locked fresher
    challenge can neither shadow an older valid one nor leak an expired/locked status as
    an enumeration signal. Underneath, the at-rest per-challenge attempt cap (default 5,
    then the challenge locks) is the last-resort bound independent of the cache-backed
    limiter. Issue / verify-fail / lockout / verify are audited — with the challenge id,
    purpose, channel and recipient, and never the code.
  - **Minimum code length.** Configuring `code_length` below 6 is floored to 6: a 10^4
    space is brute-forceable within the attempt cap once sprayed across recipients/IPs,
    so it is refused rather than silently accepted.
  - **Config.** New `cbox-id.otp.*` keys: `code_length` (floored to 6), `ttl_seconds`,
    `max_attempts`, `issue.max_per_window` + `issue.per_recipient_max`,
    `verify.max_per_window` + `verify.per_recipient_max`, the deny-by-default `channels`
    map, and `email.*` (subject / from).
  - **Testing.** `Testing\InteractsWithOtp` + an in-memory `Testing\FakeOtpChannel`
    that captures delivered codes — dogfooded by the suite, which proves the
    issue→verify lifecycle, single-use, TTL, attempt-cap + lockout, both rate limits,
    deny-by-default (unregistered channel, no-ambient-environment, cross-environment
    isolation), code-hashed-at-rest, code-absent-from-audit, and the uniform
    constant-time miss path.

### Security

- OTP is treated as an auth factor: codes are CSPRNG-generated, stored only as a
  keyed HMAC (never plaintext), single-use, TTL-bounded, attempt-capped and
  rate-limited on both issue and verify; verification is constant-time on every path
  and returns a uniform result (no enumeration / timing oracle); the plaintext code
  never appears in a return value, an audit row, a log (outside the dev-only
  `LogOtpChannel`), or an exception. Honest scope is documented: a short code's safety
  rests on the caps, not its entropy, and SMS is only as secure as SIM-swap
  resistance. New docs: `core-concepts/otp-channels.md`, `security/otp.md`,
  `cookbook/add-an-sms-otp-channel.md`, `extension-points/custom-otp-channel.md`.

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
