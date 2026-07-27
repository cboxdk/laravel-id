---
title: Feature support
description: Every non-protocol capability graded — identity, authorization, directory, governance, audit, webhooks, operations
weight: 2
---

# Feature support

Everything that is not a wire protocol. For the RFC-by-RFC record see
[Standards & conformance](../security/standards.md); for the grading vocabulary — **Full**,
**Partial**, **Contract only**, **Host-supplied**, **No** — see [Capabilities](_index.md).

## Identity & authentication

| Capability | Grade | Notes |
|---|---|---|
| Global subjects with a pluggable user model | **Full** | The host's own `User` model is resolved through config; the package owns the schema. |
| Password authentication | **Full** | Framework hasher (bcrypt/argon2id), constant-time failure path, rehash-on-login. |
| Password policy — length, reuse history, expiry, lockout, MFA and SSO mandates | **Full** | An environment sets the floor; an organization may only *tighten* it, never negotiate below it. Minimum length defaults to 12. Reuse history, expiry and lockout each default to **off** until you set them. |
| Breached-password screening | **Contract only** | The shipped default answers "not breached" for every password. See the caveat in [Standards](../security/standards.md#multi-factor-and-credentials). |
| Password complexity classes | **No** | |
| Bulk user import with lazy hash migration | **Full** | CSV or JSON via `cbox-id:users:import`; foreign hashes are refused unless you bind a verifier for the format, then upgraded to the platform hasher on first successful login. |
| Sessions — absolute TTL and idle timeout | **Full** | 8 hours and 30 minutes by default; `amr` recorded on the session. |
| "Remember me" persistent login | **No** | |
| Step-up / sudo re-authentication | **Host-supplied** | The package records `auth_time` and `amr` and stamps `acr` so your app can decide, and gives you MFA verification primitives. It ships no freshness window, no sudo mode and no re-auth challenge. |
| TOTP second factor | **Partial** | SHA-1, 6 digits, 30 s, ±1 step — fixed. Secrets sealed at rest, replay blocked. |
| WebAuthn / passkeys | **Partial** | Real verification; ES256 and RS256 only; `none` and self-attested `packed` only. **Inert until `rp_id` and `origin` are configured.** Challenge issuance is host-supplied. |
| Recovery / backup codes | **Full** | |
| Magic-link email sign-in | **Full** | Hash-only single-use token with a TTL. |
| Password reset | **Full** | Hash-only single-use token, TTL, anti-enumeration, revokes every session on reset. |
| Email verification | **Full** | Hash-only single-use token, TTL, stale-address guard. |
| One-time passcodes (OTP) | **Partial** | Keyed HMAC at rest (HKDF subkey off the master key), decoy hash for uniform timing, per-recipient and per-IP rate limits, per-challenge attempt cap. **Only the email channel ships** — plus a log channel for development and a null channel. |
| SMS / voice / push OTP | **Contract only** | `OtpChannel` is the extension point; no driver and no provider SDK ships. |
| Login lockout | **Partial** | Implemented, serialized under a row lock, audited — but the threshold defaults to `null`, so it is **off until a policy sets it**. Window and duration are fixed at 15 minutes. |
| Federated sign-in and explicit account linking | **Full** | Provider-agnostic `FederatedPrincipal`. A federated identity is never merged into an existing account by email; that path is refused so linking stays deliberate. |
| Named social providers (Google, GitHub, Microsoft buttons) | **Host-supplied** | The framework provides the provider-agnostic linking path only. |

## Authorization

| Capability | Grade | Notes |
|---|---|---|
| Roles and permissions, scoped per organization | **Full** | Uniqueness is per `(organization, client_id, role name)`, so two apps can own a role of the same name. |
| Hierarchy-aware roll-down | **Full** | A role granted at an ancestor organization applies to its descendants, via a closure table. |
| Wildcard permissions (`billing.*`) | **No** | Permission matching is exact-name equality. |
| Role inherits role | **No** | Only *organization* hierarchy inherits; there is no role graph. |
| Relationship-based authorization (ReBAC) | **Partial** | A real tuple store with recursive userset expansion, cycle protection and a depth limit of 12. **Not cached** — every check is live queries, two per node. No policy DSL, and no compatibility with any external authorization-service wire protocol. |
| Policy decision point | **Partial** | The PDP decides from **ReBAC tuples only**. RBAC permission checks run on their own path and do not pass through it — treat them as two authorization systems that meet at the decision endpoint, not one. |
| Entitlements fed by your billing engine | **Full** | Version-tagged cache invalidation, environment-scoped keys, and a random re-seed on counter loss so a stale snapshot cannot resurrect. Never holds billing state. |
| Authorization decision endpoint (`POST /oauth/decisions`) | **Full** | Permission and entitlement checks in one round trip, batch capped (default 50) so one request cannot become an unbounded number of queries. |
| Entitlement claims embedded in the access token | **Full** | Coarse entitlements ride as an `ent` claim with a staleness signal; instant-critical ones stay live. |
| Bring-your-own RBAC driver | **Contract only** | Switching the driver away from `builtin` binds stubs that refuse every call until you supply an adapter. |
| Group → role mapping from the directory | **Full** | SCIM group membership changes reconcile role assignments. |
| App-declared role manifests | **Full** | Apps publish their own roles/permissions over HTTP; fetching is SSRF-guarded and syncs hourly. |
| XACML | **No** | |

## Organizations & tenancy

| Capability | Grade | Notes |
|---|---|---|
| Environments as a hard identity boundary | **Full** | Own users, own keys, own issuer. Deny-by-default: no environment in context means zero rows. |
| Organizations, memberships, invitations | **Full** | Invitations are explicit-acceptance — creating one grants nothing. Last-owner removal is refused. |
| Reseller / parent hierarchy | **Full** | Closure table with loop-refusing subtree moves. |
| Groups and resource grants | **Full** | Both write ReBAC tuples. |
| Custom domains | **Partial** | DNS TXT challenge, verification, and promotion to issuer host. Deliberately TLS-agnostic — certificate issuance is yours. |
| Home-realm discovery (email domain → SSO connection) | **Partial** | The lookup primitive ships and is environment-scoped, but there is **no endpoint and no caller** — routing a login by email domain is yours to wire. |
| User API tokens | **Full** | Capped at the issuing member's role. |
| Platform control plane — operators, accounts, projects | **Full** | Accounts sit above the environment boundary; account members are ordinary subjects in the platform-root environment rather than a second credential store. Signed, expiring, purpose-pinned handoff into a tenant environment. |

## Directory & provisioning

| Capability | Grade | Notes |
|---|---|---|
| Inbound SCIM 2.0 server | **Partial** | See [Standards](../security/standards.md#scim-20-inbound-provisioning-server) for the per-section detail. |
| Directory pull connectors | **Full** | Google Workspace (Admin SDK) and Microsoft Entra (Graph). Both normalise into the same value objects and run the same reconciliation as SCIM push. Neither is a SCIM client — they are proprietary REST APIs shaped into SCIM. |
| Immediate deprovision | **Full** | Deactivation drops membership and **revokes sessions immediately**. |
| Outbound SCIM provisioning | **Partial** | A generic SCIM 2.0 client against any endpoint, with bearer or client-credentials auth, a durable outbox, retries, dead-lettering, per-connection circuit breaker, and a resolve-once IP-pinned SSRF guard. **Users only — no group or membership push.** No vendor-specific connectors. |
| Deprovision policy | **Full** | Per connection: deactivate (`active: false`) or delete. |

## Governance

| Capability | Grade | Notes |
|---|---|---|
| Access-certification campaigns | **Full** | Snapshot, certify/revoke, apply on close. Revocations are genuinely applied, and a refusal (last owner, say) is recorded with its reason rather than dropped. Un-reviewed items default to *revoke*. Overdue campaigns close on a schedule. |
| Segregation of Duties | **Partial** | Pre-grant gate plus conflict scanning, with reasoned decisions. **Ignores hierarchy-inherited roles.** |
| Scope of both | **Partial** | RBAC role assignments and organization memberships only. **Entitlements and ReBAC tuples are out of scope** — ReBAC tuples have no enumeration surface to certify against. |

## Audit & observability

| Capability | Grade | Notes |
|---|---|---|
| Append-only hash-chained audit trail | **Full** | `SHA-256(canonical payload ‖ previous hash)`, one chain per environment and scope, with the environment id inside the hash so a row cannot be moved between environments undetected. Appends serialize on an anchor row and retry on unique-constraint collision. |
| Signed checkpoints | **Partial** | A JWS over `{scope, up_to_sequence, root_hash}` closes the tail-truncation hole that a bare chain leaves open — but **nothing creates checkpoints automatically**. Until your app or scheduler calls for one, deletion of the chain's tail is not detectable. |
| Tamper-*proof* storage | **No** | This is tamper-**evident**, not tamper-proof: no WORM storage, no external notarization or transparency log, and no per-entry signature. Someone with database write access can still delete rows — the chain and checkpoints are what make it *visible*. |
| Audit query and SIEM pull stream | **Full** | Filtered, paginated reads plus a sequence cursor. |
| Outbound SIEM streaming | **Partial** | Transactional outbox committed with the audit entry, at-least-once, pumped every minute. **One transport: HTTP(S).** Splunk HEC, Elastic ECS, GELF 1.1, ArcSight CEF and generic JSON are five *formats* over it. **No** file, S3, syslog-transport or OCSF sink. |
| Retention / pruning | **Full** | `cbox-id:prune` sweeps ten tables with per-table defaults and a dry-run mode. `audit_logs` is **deliberately never pruned** — pruning below a checkpoint would break verification, and pruning up to one would remove the anchor. |

## Events, webhooks & hooks

| Capability | Grade | Notes |
|---|---|---|
| Transactional outbox for domain events | **Full** | Emitted inside the caller's transaction, so a rolled-back change cannot leave an event behind. |
| Delivery guarantee | **Partial** | **At-least-once**, explicitly — subscribers must be idempotent. Exactly-once is neither claimed nor implemented. |
| Relay backlog observability | **Full** | Logged every pass, warns above a threshold, and `cbox-id:events:backlog` exits non-zero on demand for alerting. |
| Outbound webhooks | **Full** | Asynchronous, uniqueness-locked, exponential backoff to a 12-attempt dead letter, stranded-delivery rescue, per-endpoint circuit breaker, gap-free per-endpoint sequence, HTTPS-only DNS-pinned SSRF guard. |
| Webhook signature | **Full, proprietary** | HMAC-SHA256 over `"{timestamp}.{body}"`, sent as `X-Cbox-Timestamp` and `X-Cbox-Signature: t=…,v1=…`. This is **not** the Standard Webhooks specification — do not point a spec-compliant verifier at it. |
| Webhook replay protection | **Partial** | The timestamp is signed so a receiver *can* enforce a tolerance window, but **no receiver-side verifier and no tolerance constant ship** — that half is yours. |
| Event catalog | **Full** | 27 typed event types plus a `*` wildcard subscription. |
| Inline hooks (external actions) | **Full** | Six points — token minting, post-login, pre/post registration, pre/post password change — each with its own fail policy (`token_minting`, `pre_registration` and `pre_password_change` fail **closed**). In-process handlers or signed, SSRF-guarded HTTP calls with pinned DNS and no redirects. A deny at a non-vetoable point is audited and folded to an allow rather than silently ignored. |

## Cryptography & secrets

| Capability | Grade | Notes |
|---|---|---|
| Envelope encryption for secrets at rest | **Full** | XChaCha20-Poly1305-IETF (libsodium), random nonce per message, bound to a context string as AEAD additional data. Not AES-GCM. |
| Signing key management and rotation | **Full** | RSA-2048, P-256 or Ed25519; private keys sealed per-`kid`; `cbox-id:keys:rotate` with an Active→Rotating→Retired overlap so in-flight tokens keep verifying. |
| Master-key rotation | **No** | There is no re-encrypt/rewrap routine. The vault's `key_version` column is written as a constant and never read. Plan master-key custody accordingly. |
| HSM / KMS integration | **Contract only** | `SecretBox` is the swap point; no AWS KMS, Vault or PKCS#11 implementation ships. |
| Token vault for downstream credentials | **Full** | Seals third-party credentials and brokers short-lived, deny-by-default leases to clients. Uniform refusal with no enumeration oracle; the real reason goes to the audit log only. Per-grant TTL can only shorten the default. Secret rotation is supported (master-key rotation is not — see above). |

## Operations & tooling

| Capability | Grade | Notes |
|---|---|---|
| Artisan commands | **Full** | Fourteen, including `cbox-id:install`, `cbox-id:doctor`, `cbox-id:users:import`, `cbox-id:directory:sync`, `cbox-id:provisioning:sync`, `cbox-id:keys:rotate`, `cbox-id:events:relay`, `cbox-id:events:backlog`, `cbox-id:prune`, `cbox-id:audit-streams:pump`, `cbox-id:governance:close-overdue`. |
| Scheduled work | **Full** | Manifest sync, audit-stream pump, governance auto-close and the event relay all register themselves, config-gated and `withoutOverlapping`. See [Operations](../operations/_index.md) — **the platform delivers nothing without a queue worker and scheduler running.** |
| Usage metering | **Full** | Per-day, per-environment, per-organization counters fed off the outbox, with a reconciler for drift. **Metering never enforces** — enforcement belongs to entitlements. |
| Testing helpers | **Full** | Every module ships `InteractsWith*` traits and fakes, and the package's own suite uses them. |
| Database engines | **Partial** | SQLite, MySQL 8.0.13+ and PostgreSQL 14+ are green in CI. MariaDB migrates but the suite is not green. SQL Server has never been run. See [Requirements](../requirements.md) — that page is the authority, not this row. |
| Telemetry / metrics runtime | **No** | Deliberate: a library must not force an observability stack on its host. |
| Admin console, hosted login, consent screen | **Host-supplied** | This package is UI-free. |

## Client SDKs

First-party client libraries wrap sign-in, the profile/account redirect, back-channel token
exchange, webhook-signature verification, the Token Vault and app-manifest publishing. They
are **separate packages** — installing `cboxdk/laravel-id` does not install them, and their
own repositories are the authority on what they support.

| SDK | Package |
|---|---|
| JavaScript / TypeScript | `@cboxdk/id-js` |
| React | `@cboxdk/id-react` |
| Vue / Nuxt | `@cboxdk/id-vue`, `@cboxdk/id-nuxt` |
| Python | `cbox-id-client` |
| Go | `github.com/cboxdk/id-go` |
| Laravel / PHP | `cboxdk/laravel-id-client` |
