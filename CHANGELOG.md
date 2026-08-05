# Changelog

All notable changes to `cboxdk/laravel-id` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Confirmed security vulnerabilities and their fixes are cross-referenced under
**Security** below and in the repository's security advisories.

**Released entries are immutable.** A changelog is a historical record: what an entry
said at the time it shipped is part of what shipped. Entries below the newest released
heading are not edited for wording, tone or policy — only appended to, and only with a
dated note that says what changed and why. From 0.56.1 onward the house style avoids
naming competitor products in prose; that applies to entries written from here on and is
deliberately NOT applied backwards, because a silent rewrite of shipped history costs
more trust than the wording it removes.

## [Unreleased]

### Fixed

- **The liveness probe no longer depends on the cache being reachable.** `/up` carried
  `throttle:300,1`, and `ThrottleRequests` writes to the default cache store — so the one
  endpoint whose job is to answer "is this process alive" could not answer without Redis
  or the database. A blip in either failed liveness on every instance at once, the whole
  fleet restarted together, and each replacement crash-looped against the same dependency
  it was waiting to recover. The handler is a static `{"status":"ok"}`: there is no cost
  to limit, and no limiter worth taking a dependency for.

## [0.91.1] - 2026-08-04

### Changed

- **`AccountRole::Billing` can no longer be assigned.** 0.91.0 mapped it to `Viewer` and
  described that as losing only `canManageBilling()`, which nothing asks for. That was
  incomplete, and the host console's role/page matrix is what caught it: a Viewer may read
  the member roster and a Billing role may not, so the mapping GRANTS access to PII rather
  than merely dropping an unreachable capability. No organization role both reads the plan
  and refuses the roster, so the mapping cannot be made faithful — and widening access to
  PII is the wrong direction to fail in. The case remains, so rows that already carry it
  keep casting and keep their account-plane refusal; it is simply no longer offered.

## [0.91.0] - 2026-08-04

### Changed

- **An account member's membership now says what they hold.** `attachSubject()` wrote a
  neutral `MembershipRole::Member` for everybody, deliberately: `AccountRole` on the member
  row was the single authority for account capabilities, and mirroring it would have been a
  second truth to drift. That was right while the console asked the member row. The console
  asks the MEMBERSHIP now, so a neutral role is not an abstention — it is the wrong answer
  to the only question, and it made an account's own owner a plain member of the
  organization they own. `AccountRole::asMembershipRole()` is the one definition of how the
  two vocabularies line up; `setRole()` carries a change onto the membership so the two
  cannot separate on the first role change; and `2026_08_06_000200` repairs the rows the
  earlier backfill left neutral.

  **`Billing` maps to `Viewer`,** which is the one case that loses something.
  `MembershipRole` has no billing case and should not gain one: `canWrite()` is "not a
  Viewer", so a new role would arrive holding write access to every organization on every
  tenant, and correcting that changes what write means for everybody. Viewer keeps the
  reachable half — reading the plan — and drops `canManageBilling()`, which no page and no
  route in the product asks for.

### Added

- **`MembershipRole` gains the capability vocabulary the account plane needed.**
  `canReadMembers()`, `canReadBilling()`, `canManageEnvironments()` and
  `supportsEnvironmentScoping()`. None of these are account-specific: an organization's own
  console has the same needs, and the roster restriction in particular is general — a
  Developer is frequently a CI or agent credential rather than a person, and a leaked one
  must not enumerate the team. `canManageEnvironments()` is deliberately NOT `canWrite()`,
  which admits the generic `Member`: standing up an environment grants a live
  environment-admin session on that tenant's host.

### Fixed

- **The last owner of an account can no longer be demoted.** `remove()` has always refused
  to delete an owner, on the grounds that it could orphan the account; re-roling the same
  owner to Admin orphaned it just as thoroughly and was allowed. It went unnoticed because
  only the member row was written and nothing objected. Refused up front, before anything
  is written, so the account and its organization cannot record different outcomes.

## [0.90.0] - 2026-08-04

### Removed

- **The account plane's own second factor.** `account_mfa_factors`,
  `account_mfa_recovery_codes` and `account_webauthn_credentials` are dropped, along with
  `AccountMemberMfa`, `AccountPasskeys` and their implementations and models. They were
  built on the premise that an account member is a separate principal from a subject —
  "a SEPARATE subsystem from operator and subject MFA", as the original migration put it.
  Unified account identity removed that premise: an account member IS an ordinary subject
  in the platform root.

  It had already stopped being enforceable. Once the deployment's one sign-in served the
  platform root, a member holding an account TOTP signed in at `/login` against their
  SUBJECT credential and reached the console with a password alone — nothing on that path
  had reason to consult a table keyed by member id. What remained was the appearance of a
  factor, and a store that can still be written but is never checked is worse than none:
  it reads as protection in a schema diagram, it accumulates secrets that must be sealed
  and rotated and disclosed in a breach, and whoever enrolled believes they are protected.

  A member's second factor is their SUBJECT's — enrolled through `Identity\Contracts\Mfa`
  on the account security page, enforced by the host's password door, with the same
  recovery codes every other person on the deployment gets. **No rows are carried across**:
  a sealed TOTP secret belongs to the principal it was enrolled against, and silently
  re-pointing one would produce a factor its owner never agreed to. Anyone who had enrolled
  on the account plane re-enrols. `down()` rebuilds the tables; it cannot rebuild the rows,
  and says so.

### Fixed

- **Every account that predates `accounts.organization_id` is now homed.** The column was
  added nullable in `2026_07_25_000400` with no backfill, and it is written in exactly two
  places, both at account-CREATION time — so every account created before that date had
  null, permanently. That is not cosmetic: the console asks whether the organization being
  administered is the one this account owns, and against null that is false for every
  organization, so an account owner saw no projects, no members, no API keys, no billing
  and no settings — the whole identity-platform area, absent for the person who owns it.
  No test could see it, because every fixture in both suites builds its account through
  `AccountProvisioner::provision()`, which homes it on the way past; the one state a real
  deployment was in was the one state nothing here could produce. It is also not only a
  legacy problem — `homeAccount()` returns silently when there is no platform root yet,
  which is precisely the window the installer and the first-run screen run in.

  The migration writes raw rows rather than calling `OrganizationService::create()`: a
  backfill runs during a deploy, and a thousand accounts should not put a thousand domain
  events on a queue and a thousand entries on the audit chain. It is ordered ahead of
  `2026_08_06_000100`, whose own backfill reads `accounts.organization_id` and would
  otherwise have written null the whole way through.

### Added

- **An organization can own IdP products directly.** `accounts.organization_id` has
  always said an account *is* an organization in the platform root — members and a
  payment method bolted onto it. `projects.organization_id` now records that link
  directly instead of re-deriving it through the account plane, and `Organization` gains
  `projects()` (has-many) and `environments()` (has-many-through the project, so there
  is no second denormalized column to drift). `Platform\Contracts\OrganizationProjects`
  adds `forOrganization()` and `ownedByOrganization()` for the console case where only
  the id is in hand; `DatabaseProjects` implements it alongside `Projects`.

  Both relations cross OUT of the environment scope, which is safe because of the
  PARENT, not the child: a project owns environments and cannot itself live inside one,
  while `Organization` is environment-owned, so the model is unobtainable from any other
  environment — deny-by-default refuses it even by primary key — and the child query is
  keyed on that organization's id.

  The column is stamped on the model's `creating` hook rather than at a call site, so a
  host calling `Project::create()` directly gets it too; a project that missed it would
  read as healthy from the account side and be invisible from the organization side, a
  silent one-directional split of the same fact. Existing rows are backfilled per homed
  account, idempotently. `(organization_id, slug)` is unique, mirroring the
  `(account_id, slug)` key beside it.

  **Purely additive.** `Account`, `AccountMember`, `AccountRole`, `AccountProvisioner`
  and every existing signature are untouched, and `projects.account_id` stays NOT NULL —
  an organization can be *read* as the owner today, but owning a project with no account
  behind it needs that column to become nullable, which is a separate, subtractive step.
  `Account::$environment_limit` is deliberately NOT copied to organizations: the enforced
  limit lives on the project (`EnvironmentLimitReached` is keyed there) and the account
  column is only a provisioning seed, so a third copy would be a number that can disagree
  with the one enforced.

- **The account-role / membership-role correspondence, written down.**
  `docs/core-concepts/account-and-membership-roles.md` maps `AccountRole` to
  `MembershipRole` in both directions. They are not the same set under two names: four
  cases are shared, `Billing` exists only on the account plane and `Member` only on the
  organization plane, and the predicate surfaces do not line up —
  `MembershipRole::canWrite()` is broader than `AccountRole::canManageEnvironments()`, so
  mapping `Billing` onto `Member` grants write access to a billing-only role.
  `Viewer` is the safe floor in both directions, neither round-trips, and billing
  capability is not representable on the organization plane at all. The enums are
  deliberately NOT unified; a test locks every claim on the page so a new case turns it
  red rather than stale.

### Fixed

- **An account member's password reset did not end their sessions.** `resetPassword()`
  reaches the subject through `Subjects::setPassword()`, which writes the credential and
  nothing else — `PasswordResetService` and `AdminPasswordService` each revoke alongside
  it, and this door inherited the write without the revocation. What stood in for it was
  `account_members.session_version`, a stamp a host re-checked on every resolve of its own
  member session.

  That worked only for as long as a member session was its own thing keyed on a member id.
  A member is an ordinary subject in the platform root, and a host that signs them in the
  ordinary way gives their browser an ordinary subject session — which no column on
  `account_members` can reach. So on any host that has finished the unification, a reset
  left every other session the member held wide open, including the one a thief was
  sitting in. `resetPassword()` now calls `SessionManager::revokeAllForUser()` inside its
  existing transaction, in the platform root's scope.

  The stamp is unchanged and still bumped: its other job is making a reset LINK single-use,
  and that is a different question from ending a session.

- **Accepting an invitation could resurrect sessions from before the account was left.**
  Removing a member deactivates their subject but does not revoke its sessions — the
  per-request active check is what holds them out. Accepting a later invitation reactivates
  that same subject (a subject is never re-created for an address that already has one), so
  those sessions came back to life next to a password that had just been replaced.
  `activate()` now revokes alongside the credential write, for the same reason
  `resetPassword()` does.

## [0.89.1] - 2026-08-04

### Fixed

- **A pinned relying party could win with an origin no browser reports.** 0.89.0 let a pin
  survive where it was a valid answer for the environment's host — but it validated only
  the `rp_id`, not the origin. The id is what an authenticator scopes a credential to; the
  ORIGIN is what the verifier compares byte-for-byte against the browser's
  `clientDataJSON`. An operator following our own advice to pin "usually the registrable
  domain" for BOTH keys — `rp_id=acme.com`, `origin=https://acme.com`, on an environment
  serving `id.acme.com` — got a pin that won and then failed every registration and every
  assertion with "origin mismatch". `RelyingParty`'s own docblock warns that the pair can
  be individually plausible and jointly impossible; the guard checked one member of it.

- **`cbox-id:doctor` could not name that state, by construction.** It compared the pinned
  party against the party in force — and once a pin wins, those are the same object, so
  both halves matched and it reported OK for every pin that won, including one that fails
  every ceremony. It now compares the pin against the HOST that will actually answer,
  which is the question an operator needs answered.

## [0.89.0] - 2026-08-04

### Fixed

- **The canonical-issuer redirect held the whole protocol surface; now it holds only the
  metadata.** 0.88.0 redirected every endpoint on an alias host to the canonical issuer.
  That is right for the documents whose identity IS the host, and wrong for everything
  else: SCIM has no issuer concept at all, and a cross-origin redirect makes HTTP clients
  drop `Authorization` — so Okta and Entra provisioning that worked on the alias began
  answering 401 the moment a tenant verified a custom domain. `/oauth/token`,
  `/introspect`, `/revoke` and `/userinfo` are the same shape: they authenticate by
  credential, not by issuer identity.

  Only the four discovery documents and the SAML IdP metadata redirect now, and they
  answer **302 with `Cache-Control: no-store`** rather than a cacheable 301. A 301 is
  heuristically cacheable forever, so clearing a custom domain used to strand every client
  that had seen one, with no way to unwind it. A non-safe method is refused rather than
  redirected.

  The browser surface is deliberately left alone. Nothing it returns names a host — the
  `iss` of the authorization response, the id_token and the SAML `Issuer` are canonical
  whichever host answered — a discovery-driven client already arrives at the canonical
  endpoint, and redirecting it is precisely what an SP's `form-action` CSP blocks.

- **An upgrade could silently lock out every passkey holder on an on-prem deployment.**
  0.88.0 derived the relying party from the environment's host whenever the environment
  had one. WebAuthn allows an RP id to be the origin's host OR a registrable suffix of it,
  and our own documentation tells operators to pin "usually the registrable domain" — so
  `rp_id=acme.com` on the single environment serving `id.acme.com` is a correct pin with
  credentials enrolled against it. Overriding it moved the id, and an authenticator is
  never even OFFERED a credential scoped to a different id: locked out, silently, with no
  error and no way back, because no credential stores the id it was enrolled under.

  A pin now survives where it is still a valid answer for the host in front of it. It does
  NOT survive on a tenant label under a configured base domain, where a shared id would
  offer one tenant's passkey on another tenant's sign-in page — and nothing is stranded
  there, because a tenant passkey could never have enrolled in the first place.

- **`cbox-id:doctor` reported a pin as being in force when it was not.** It compared only
  the origin, and the pair that strands users has identical origins and differs only in the
  id. It now compares both halves and names what a ceremony actually runs as.

## [0.88.0] - 2026-08-04

### Fixed

- **Discovery advertised an `issuer` that was not the host serving it.** An environment
  resolves from either its verified custom domain or `{slug}.{base_domain}`, and both kept
  serving the whole protocol surface — but the issuer was the custom domain
  unconditionally. So a tenant onboarded at `acme.example.com` that later verified
  `id.acme.com` had every existing relying party fetch discovery from the subdomain and
  receive a different `issuer`. That is a MUST in OIDC Discovery §4.3 and RFC 8414 §3.3;
  conformant clients throw. Every integration broke at once, from a config change nobody
  would associate with them.

  `CanonicalIssuerHost` now redirects the alias to the canonical host — 301 for safe
  methods, **308** for the rest, because a 301 on `POST /oauth/token` lets a client rewrite
  to GET and drop the grant body. Deployment-wide issuers (platform root, single-tenant,
  on-prem) are deliberately not redirected: their issuer is operator-configured and
  host-independent, so internal load-balancer names and health probes keep working.

  **Upgrade consequence:** a tenant that has already verified a custom domain now has ONE
  issuer, and its subdomain becomes a redirect. Relying parties configured against the
  subdomain must be repointed. The break is now explicit and one-time at verification
  instead of silent and permanent.

- **WebAuthn was single-origin, so passkeys could not work on any tenant host.** The
  relying-party id and origin were one deployment-wide pair, compared byte-for-byte against
  what the browser reports. Subject-plane passkeys are served on tenant hosts only, so with
  the pair set to the platform apex every tenant's enrolment and assertion failed with
  "origin mismatch" — a shipped, documented, tested feature inert for the entire customer
  base.

  `RelyingParties` now derives the pair per environment from its issuer, and the id and the
  origin travel together in one value object: read as separate config keys they can each be
  individually plausible and jointly impossible. The RP id is the environment's full host,
  not a registrable suffix — a suffix would offer one tenant's passkey on another tenant's
  sign-in page.

### Changed

- **`Subject` carries its status**, so the per-request re-check that refuses a deactivated
  account no longer costs a second read of the row `find()` already loaded. Nullable rather
  than defaulting to active: a host-bound resolver written before the field says nothing,
  and null means "ask the contract", so an unaware implementation keeps paying the query
  and keeps being right.

- **`RequestLifetime`** — a scoped marker whose identity is "this request or job". Hot
  objects that are singletons, or captured by them, cannot be memoised by binding them
  `scoped`: `forgetScopedInstances()` unsets the binding and cannot reach an instance
  something else is holding, so the first request's memo would be pinned forever. Comparing
  a held token against the one the container resolves works whoever holds the memo.
  `CachedEntitlements`, `EnvironmentIssuerResolver`, `DatabaseAuthPolicies` and
  `PlatformRoot` use it.

  `PlatformRoot::model()` memoises only when a row is FOUND — "there is no platform root"
  is the one answer that flips inside a request, and a memoised null would leave the
  operator the installer just created on the bootstrap hash.

- `WebhookRegistry::forOrganization()` — `matching()` read every active endpoint per event
  type and filtered in PHP. The app's own catalogue lists 24 event types; aligning the
  config with it would have made that 24 full reads per render.

- `registration_client_uri` comes from the issuer resolver rather than `url()` — it was the
  only endpoint in the document that did not.

## [0.87.3] - 2026-08-04

### Security

- **A deactivated subject authenticated with ANY password.** `DatabaseAccountMembers::verifyPassword()`
  refused a deactivated subject with `! $this->hasher->check($password, $this->dummyHash())`.
  The dummy verify exists to burn time and have its result discarded; the negation made it
  the answer. A dummy hash matches nothing, so `check()` returned false and `!false`
  authenticated. "Deactivated subject holding an active membership" is not exotic — it is
  an unaccepted invitation, and it is a removed member. The caller mints a session on that
  answer and clears the failure counters, so the session goes live the moment the subject
  is reactivated.

  It survived because the branch is only reached with a WRONG password by an attacker;
  every honest test supplies the right one, where broken and fixed agree. The refusal is
  now a statement block that cannot return the discarded value, matching
  `DatabasePlatformOperators::verifyPassword()`, which always expressed the same policy
  correctly. Regression test supplies a garbage password and falsifies.

- **SCIM: `PATCH` group with a bare `members[...]` value filter detached every member.**
  `members[value eq "x"].display` was refused; `members[value eq "x"]` was not — it
  contains no `].` and does not begin with `members.`, so it cleared both guards, reached
  `sync(valueIds(…))` with a non-list value, and emptied the group. 200 returned,
  membership-changed fired, every role mapped from that group was revoked for every
  member, and the connector recorded a success so it never retried or re-synced. Silent on
  both sides, which is what made it worse than an error.

  `add` and `replace` now refuse any filtered `members` path. `remove` with that exact
  path is how an IdP detaches ONE member and continues to work.

## [0.87.2] - 2026-08-04

### Fixed

- **A member's password reset no longer leaves their other sessions alive.** The security
  stamp on `account_members` invalidated MEMBER sessions, and that was the whole of
  log-out-everywhere while a member session existed. It is a host's decision to stop
  keeping one — the credential of record is the subject, so a second session for the same
  person is a second place to ask who they are — and the moment a host makes it, the
  control silently stops covering anything: `Subjects::setPassword()` does not revoke.

  `resetPassword()` now revokes the subject's sessions inside its existing transaction.
  The stamp still moves; its other job, making a reset link single-use, is a different
  question and is unchanged.

- **`activate()` revokes too.** Removing a member deactivates their subject without
  revoking its sessions, so accepting a later invitation resurrected the old ones beside a
  freshly-replaced password.

## [0.87.1] - 2026-08-04

### Fixed

- **An operator carried across from before the unification could no longer sign in.**
  0.87.0 made `platform_operators.subject_id` nullable and left the attaching to
  `verifyPassword()`: the local hash stayed the credential and the subject was created on
  that operator's next successful sign-in — the only moment the plaintext is available to
  seed one. That was correct while a sign-in existed that verified against the local hash.

  It stops being correct the moment a host makes operator authority a permission on the
  ordinary sign-in and retires the separate operator login form, because that form was the
  only caller reaching the bootstrap window. On an upgraded deployment every existing
  operator then has no subject, no account to sign in as, and no door that consults their
  hash — locked out of the platform they run, by an upgrade that reports success.

  A migration now attaches a subject to every operator that lacks one. The plaintext is
  gone but the hash is not, and it does not need re-deriving: both tables hash with the
  configured driver and both models pass an already-hashed value through untouched, so the
  credential moves and the password keeps working. An operator who is also an account
  member is pointed at the subject they already have rather than given a second one, and
  their live password is not touched. The address is NOT marked verified — the operator
  table never asked, and claiming otherwise would hand a confirmed address to step-up
  gates that rely on it meaning something.

  A migration rather than a command, deliberately: a command is a step someone has to know
  about, and the failure mode for not knowing is that nobody can administer the platform,
  discovered after the deploy by the person who can no longer fix it.

## [0.87.0] - 2026-08-04

### Changed

- **A platform operator is a person now, not a second credential store.**
  `platform_operators` held an email and a bcrypt hash and nothing else. Everything that
  protects a sign-in on this platform lives on the SUBJECT — password policy,
  breached-password refusal, lockout after repeated failures, TOTP, passkeys, step-up,
  session revocation — and an operator had none of it, because it was never given any.
  The widest reach in the product sat behind the weakest door, and it was weakest
  precisely because it was separate.

  `platform_operators.subject_id` points at an ordinary subject in the platform root, and
  `verifyPassword()` asks that subject. Account members already work this way; this is the
  same change for the same reason, and it follows the same shape.

  Nothing breaks on upgrade. The column is nullable, the local hash remains the credential
  for an operator created before a platform root existed, and the subject is attached on
  that operator's next successful sign-in — the only moment the plaintext is available to
  seed it. The hash column stays until every row has a subject; removing it earlier is a
  deployment that cannot authenticate.

  A deactivated subject now refuses the operator immediately rather than at the next
  session boundary, which for an identity with cross-environment reach is the point.

### Added

- **`PlatformOperators::findBySubject()`** — the operator record a signed-in subject
  holds, or null. With the operator unified onto the subject store, "is this session
  staff" becomes a question about the session a host already has, so a console can gate
  the platform pages as a PERMISSION instead of standing up a second sign-in beside the
  first. The separate operator door only ever existed because there was a separate
  operator credential.

  Suspended operators are excluded inside the lookup rather than by the caller. Authority
  now rides an existing session and suspending an operator has never revoked their subject
  sessions, so a status check left to each call site fails open — the suspended operator
  keeps every platform page in the session they already hold.

## [0.86.0] - 2026-08-03

### Added

- **One provider catalogue, with capabilities.** Providers were named in two registries
  that shared nothing: `ProviderCatalog` held eleven entries for sign-in — issuers,
  scopes, profile maps, setup steps, documentation — and `DirectoryProvider` held three
  for user sync. Google and Entra were in both, connected by nothing but the word.

  The administrator paid for that. The directory screen could not show the guide that
  already existed here for the same provider, so somebody who had just finished
  connecting Google for sign-in was handed an empty credential form and left to work out
  alone that a directory needs a service account with domain-wide delegation rather than
  the OAuth client they had just made. Two registries meant the product knew the answer
  and had no way to say it.

  A `ProviderTemplate` now carries what it can DO — `ProviderCapability::Login`,
  `ProviderCapability::Directory` — as a typed `ProviderCapabilities` set, and
  `ProviderCatalog::withCapability()` is how a screen asks for the providers it is there
  to set up. The capabilities are **derived from the entry's contents, never declared
  beside them**: a hand-written list is a claim that can be false, and a template
  claiming `directory` with no setup on it would put a provider in the console's list
  that the console cannot then show one field for.

- **The directory half is its own guide, because it is its own job.** `DirectorySetup`
  carries the steps, the vendor documentation URL, and the credentials the connector
  actually reads — separately from the login steps, which describe a different act
  entirely. Connecting Google for sign-in is an OAuth client and two pasted strings;
  connecting the same Google as a directory is a service account, a numeric client ID,
  and a domain-wide delegation grant made in a different console. One flat list of steps
  could only ever have been right for one of them, and an administrator following the
  wrong one gets to the end before finding out.

  The declared credentials are driven through the real connectors in the suite: the full
  set must satisfy them, and dropping any single one must not. A setup form built from a
  stale list collects fields nobody reads and misses one nobody asked for — and stores
  the connection anyway, because a credential map is just an array until something uses
  it.

### Fixed

- **The Entra directory guidance asked for half the permissions it needs.** The
  connector's own documentation named `User.Read.All` only, and the pull fetches groups
  and group members as well — so an administrator who granted exactly what they were
  told got users and, silently, no groups at all. The catalogue entry and the connector
  both now say `User.Read.All` **and** `Group.Read.All`, application permissions,
  admin-consented. The same trap exists on the Google side, where domain-wide delegation
  must carry both the user and the group read-only scopes, and the setup steps now spell
  out both.

### Notes

- `DirectoryProvider` **stays**, deliberately. It is what sits in `directories.provider`
  on every row ever written, what the connector registry is keyed by, and what the sync
  command filters on — a serialization boundary, where a rename is a migration rather
  than an edit. What it no longer does is own provider metadata; the catalogue does, and
  `ProviderCatalog::forDirectory()` is the join. Nothing about existing rows changes.

- **SCIM is not in the catalogue, and that is the design.** Everything in the catalogue
  is a service we go to, holding a credential the customer created for us. SCIM is the
  reverse — a protocol the customer's own identity provider speaks TO us, against an
  endpoint and a bearer token we mint. It has no issuer, no vendor, no client credentials
  to collect and no third-party documentation to link, because the far end is whatever
  they happen to run. An entry for it would have meant inventing a protocol and an empty
  endpoint set to make the shape fit, and would tell an administrator that "connect SCIM"
  is the same kind of act as "connect Google" when every field on that form is ours
  rather than theirs.

- Additive throughout: `ProviderTemplate` gains one trailing optional constructor
  argument, and no existing field, method or signature changed. The dependency runs one
  way — the catalogue reaches down to `Directory`'s enum, and nothing in `Directory`
  reaches up, so a host that renders no setup screen at all still syncs.

## [0.85.0] - 2026-08-03

### Fixed

- **A refresh renews the ID Token, not only the access token** (OIDC Core §12.2). The
  refresh grant returned `access_token` + `refresh_token` and nothing else. That is
  invisible while every relying party authenticates the ACCESS token — and a hard
  failure for one that authenticates the ID Token, because the credential it actually
  presents could not be renewed at all. `kubectl oidc-login` is exactly that relying
  party, as are Grafana and Vault in that mode.

  Measured against a live deployment: a client with a 300-second lifetime meant a
  browser window every five minutes, which is the behaviour `offline_access` exists to
  prevent — and the reason somebody then asks for a longer lifetime instead of a fix.

  The refreshed token keeps `iss`, `sub` and `aud` from the original, stamps a fresh
  `iat`, and binds `at_hash` to the access token returned beside it. A grant with no
  user behind it (`client_credentials`) still gets none: an ID Token asserts an
  authenticated person, and one minted for a machine grant would be an assertion about
  nobody.

  It carries **no `nonce`**. A nonce binds an ID Token to one authentication *request*
  so a client can detect replay, and a refresh is not an authentication request —
  echoing the original would hand back a token the client has already seen that nonce
  on, which is the condition its replay check exists to catch.

### Added

- **The rotation family remembers the login it descends from.** `auth_time` and `amr`
  are recorded on the refresh token, so a refreshed ID Token can describe the ORIGINAL
  authentication as §12.2 requires rather than the moment it was refreshed. Without it
  a session's asserted assurance level would fall at its first refresh, which reads to a
  relying party gating on `acr` as the user losing their second factor.

  Adds a nullable `auth_time` and `amr` to `oauth_refresh_tokens` (migration included).
  Families issued before this keep working and simply carry no authentication context —
  the claims are optional, and a missing one is honest where a fabricated one is not.

  `RefreshTokens::issue()` takes the two as trailing optional arguments; a host that has
  implemented the contract itself must widen its signature.

## [0.84.0] - 2026-08-03

### Added

- **`cbox-id:doctor` runs the host's checks too.** The doctor knows what the LIBRARY
  needs — extensions, a crypto key, signing keys, an issuer that resolves. It cannot know
  what the host application needs, and the host's misconfigurations are the ones that
  fail quietly: a deployment claiming a shape it cannot serve still boots, still answers,
  and degrades behaviour with no error anywhere.

  A host implements `Console\Contracts\HealthCheck` and adds it to the `HealthChecks`
  registry from a service provider. One command rather than a second health command,
  because two things to remember to run means the one nobody runs is the one holding the
  finding.

  Results are a typed `HealthResult` (`ok` / `warn` / `fail` plus a label and the fix)
  rather than the string-keyed array the command used internally — this crosses a package
  boundary now, and a map at a boundary is a shape every implementer has to guess at.

  A check that throws is reported as a failure and the rest still run. The contract says
  it must not throw; the registry assumes it will anyway, because the moment you most want
  a health report is when something is already broken enough to throw.

## [0.83.1] - 2026-08-03

### Fixed

- **`cboxdk/laravel-ssrf` raised to `^1.1.1`, which repairs DNS pinning for dual-stack
  hosts.** Up to and including v1.1.0 the guard emitted one `CURLOPT_RESOLVE` entry per
  validated address, but curl treats a second entry for the same `host:port` as a
  replacement rather than an addition — so only whichever address sorted last survived.
  For a dual-stack host whose AAAA sorts last (`accounts.google.com` is one) every
  pinned request was pinned to IPv6 alone, with no fallback to the IPv4 address that had
  been validated moments earlier. On a host without an IPv6 route the connection simply
  failed, with a transport error naming neither the pin nor the protocol.

  Every outbound path in this package that pins DNS was affected: OIDC discovery, the
  OIDC and OAuth 2.0 token exchanges, JWKS fetches during assertion validation, SAML
  metadata import, SCIM provisioning, webhook delivery, external action transport and
  access-control manifest fetches. Whether it actually *failed* depended entirely on the
  host's own IPv6 connectivity, so it presented as "works on my machine".

  The floor is raised rather than left at `^1.0` so the fix is guaranteed rather than
  merely permitted — `^1.0` would let an existing lock file stay on the broken v1.1.0.
  No API change on either side.

## [0.83.1] - 2026-08-03

### Fixed

- **Requires `cboxdk/laravel-ssrf` ^1.1.1.** Below that version the SSRF guard pinned
  only the LAST of a host's validated addresses — curl treats a repeated
  `CURLOPT_RESOLVE` entry for the same `host:port` as a replacement, not an addition —
  so any dual-stack federation target whose AAAA sorted last was reached over IPv6
  alone, and failed outright on a host with no IPv6 route. `accounts.google.com` is such
  a target. Every outbound path in this package goes through that guard: OIDC discovery,
  token exchange, JWKS retrieval, and the directory connectors.

  The floor is the fixed version rather than `^1.1`, because a consumer that resolved
  1.1.0 would get a package whose pinning silently discards addresses.

## [0.83.0] - 2026-08-03

### Added

- **`ConnectionType::OAuth2`.** Providers that speak OAuth 2.0 and nothing more —
  GitHub, Discord, Facebook — now have a type of their own rather than borrowing OIDC's.
  The difference is not configuration: there is no `id_token`, no discovery document and
  no signature over the claims, so what may be trusted afterwards is genuinely narrower.
  One shared type would have let a caller reach for OIDC's guarantees on a connection
  that cannot provide them. `Connections::oauth2Config()` reads it, and refuses a config
  naming an OIDC provider — driving one of those down this path would mean no `id_token`
  was ever verified.

- **A `provider` column on connections, and `catalogueProvidersFor()`.** A tenant may
  enable several catalogue providers at once (Google *and* GitHub *and* Apple), while
  `forOrganization()` answers "the organization's enterprise sign-on connection" and has
  to keep answering exactly that. Without the column the two kinds were
  indistinguishable and the first active row won whichever it happened to be — so
  enabling Google could silently become an organization's SSO, which decides where every
  one of its people is sent to authenticate. `create()` refuses a key the catalogue does
  not have, rather than storing a connection that renders a sign-in button nobody can
  complete.

  The column is nullable and existing rows become NULL, which is what they are: a
  hand-configured enterprise connection genuinely has no catalogue entry.

- **`AppleClientSecret`.** Apple's client secret is not a string anyone can paste — it
  is an ES256 JWT minted from a downloaded signing key, valid at most six months.
  Treating it as a text field is how an Apple integration stops working half a year
  after the last person touched it, on a day nobody changed anything. Minted on demand
  and cached for an hour rather than for Apple's ceiling, keyed by the material so
  rotating a key takes effect immediately instead of when a cache expires. Signed
  through firebase/php-jwt like every other signature here; the tests verify the result
  against a real EC public key rather than by parsing our own output.

## [0.82.1] - 2026-08-03

### Fixed

- **A client's token lifetime now reaches the `id_token`.** It was hardcoded at 900
  seconds, so `accessTokenTtl` shortened only the access token — and a relying party
  that authenticates the ID token never sees that one. Kubernetes is exactly that case:
  `kubectl oidc-login` presents the `id_token` as its bearer, the API server validates
  `exp` offline and never calls back, so for it the `id_token`'s lifetime IS the
  revocation window. A client registered with a 300-second TTL was getting five minutes
  on a credential it does not present and fifteen on the one it does. Found by Cortex
  driving a real `kube-apiserver` against this issuer.

  Nothing changes for a deployment that has configured nothing: the default is still
  900. The tests assert the SIGNED `exp - iat` as well as `expires_in`, because the
  response field describes the access token and a change that moved only one of them
  would look right in the response and be wrong in the credential.

## [0.82.0] - 2026-08-03

### Added

- **A provider catalogue** — Google, Microsoft Entra, Okta, Auth0, Keycloak, GitLab,
  Slack, GitHub, Discord, Apple and Facebook. Issuers, endpoints, scopes, where the
  identity sits in the response, and how to obtain the credential. What it deliberately
  does not hold is the client id and secret: those stay the tenant's, which is the point.
  Adding a provider is a new entry, not a new code path.
- **`FederationProtocol` and an OAuth 2.0 client.** GitHub, Discord and Facebook are not
  OpenID Providers — no discovery document, no `id_token` — so the generic OIDC path
  could not reach them at all. The new client exchanges a code and fetches a profile,
  mapping it through the catalogue. It is explicit about what it does and does not prove:
  that the browser controls the provider account, and nothing about the address attached
  to it.
- **Apple, with the three ways it differs declared rather than discovered**: its client
  secret is an ES256 JWT minted from a downloaded key rather than a value to paste, it
  POSTs its callback, and it sends the person's name exactly once. Each produces a failure
  that reads as something else — most sharply, a secret stored as a string that works and
  then stops six months later.
- **`Subjects::resolveFederated()`**, reporting whether the call CREATED the account. A
  first federated sign-in is a signup, with a signup's obligations: the address is
  unverified until this platform verifies it, and the person holds exactly one way in.

### Fixed

- **The `ArraySubjects` test fake merged a federated identity into an existing account by
  email** — the account-takeover the real implementation exists to refuse. A fake more
  permissive than the thing it stands in for does not merely fail to catch a regression;
  it teaches every test written against it that the unsafe behaviour is the contract.

## [0.81.0] - 2026-08-03

### Added

- **A `groups` claim on the ID TOKEN, behind a `groups` scope.** Relying parties that
  authenticate the id_token rather than the access token — Kubernetes, Grafana, Vault —
  had nothing to map to groups: our federated RBAC lived only on the access token. A
  cluster could authenticate a person correctly and then have nothing to bind a policy
  to, so every request was denied with the identity plainly right in the logs. The claim
  carries the same data the access token does (this app's declared roles plus org-wide
  ones, never another app's), and is emitted only when the scope was granted, so no
  existing client's id_token changes shape.
- **Per-client access-token TTL.** One deployment-wide value is the wrong shape once an
  issuer serves relying parties with different revocation stories. A credential a
  resource server validates OFFLINE can only be revoked by expiry — Kubernetes never
  calls back — so for that credential the TTL *is* the revocation window, and five
  minutes is a real answer to a stolen laptop where fifteen is a worse one. A browser
  session has no reason to pay for it. `NewClient::$accessTokenTtl`; null keeps the
  deployment default, so nothing changes for existing clients.

## [0.80.0] - 2026-08-02

### Security

- **A client could choose its own token audience after the user had authorized.** The RFC
  8707 `resource` parameter was read at the token endpoint, validated as an absolute URI,
  and stamped verbatim into the access token's `aud` — while nothing recorded what the
  authorization had been FOR. So any client holding a valid code could name any resource
  server at redemption and receive a token, signed by this issuer, asserting it was minted
  for that server. That is a confused deputy against every resource server that trusts the
  issuer and checks `aud`, which is exactly the check RFC 9068 tells it to make and the
  property the MCP authorization model rests on. §2.2 requires the token request's
  resource to be the one the authorization was granted for; `authorization_codes` now
  carries it, and a mismatch is refused with `invalid_target`. A redemption naming no
  resource gets the authorized one. Codes carrying none behave exactly as before — nothing
  is retroactively bound.

  Hosts must pass the authorized `resource` to `AuthorizationCodes::issue()` for the
  binding to exist; the parameter is optional and defaults to null, so an un-updated host
  is no worse off than it was.

## [0.79.0] - 2026-08-02

### Security

- **A `persistent` NameID was the subject's email address, identical at every service
  provider.** `resolveNameId()` never consulted the format — it returned whatever the
  service provider's `name_id_attribute` pointed at, which defaults to `email`. SAML Core
  §8.3.7 defines the format as an opaque, SP-specific pseudonym precisely so that two
  providers cannot match their users against one another; ours handed them a shared join
  key that was also PII. `transient` (§8.3.8, "MUST NOT be reused") was the same stable
  email forever. Persistent identifiers are now 128 random bits per (service provider,
  subject), stored in `saml_idp_name_ids` so one provider's identifiers can be reissued
  without touching any other's; transient ones are minted per assertion and recorded on
  the session row, so Single Logout still resolves them. `emailAddress` and `unspecified`
  are unchanged. The conformance tests asserted the URN strings and the metadata but
  never the value, which is how this passed a conformance suite.

## [0.78.0] - 2026-08-02

### Security

- **A captured SAML `LogoutRequest` was a permanent, unauthenticated logout against the
  person it named.** The relying-party half of Single Logout verified the signature and
  nothing else — no freshness bound and no single-use claim, while the identity-provider
  half has enforced both since it was written. The message arrives as a query string in
  the user's browser, so a copy survives in history, proxy logs and any leaked `Referer`;
  anyone holding one could end that person's sessions again after every re-login, forever.
  onelogin checks `NotOnOrAfter` only when the message carries one, and most identity
  providers do not send one on a logout. Both bounds are now enforced, with the replay key
  scoped to the connection rather than the identity provider's EntityID — two tenants may
  federate to the same IdP, and a shared key is one tenant able to burn the other's
  message ids.
- **`saml_idp_sessions` carried a 30-day expiry that nothing enforced.** The release notes
  told operators records are kept 30 days and the constant's own docblock said a later
  logout "has nothing to resolve and is refused" — but the lookup had no expiry predicate,
  so a service provider that federated a user once could end that person's sessions
  indefinitely. A bound nobody checks is a comment.

### Fixed

- **The SAML HTTP-POST binding could not work under any real content-security policy.** A
  self-submitting form aimed at a service provider's ACS is, to a browser, exactly the
  shape `form-action` exists to refuse, and its auto-submit is exactly what a `script-src`
  without `'unsafe-inline'` exists to refuse. A host that hardened its headers broke its
  own federation: the assertion was built, signed, and never delivered — the user watched
  a blank page and the service provider was never told anything happened. There is no
  PHP-level symptom, which is why it shipped. `SamlResponse::toPostBinding()` now returns
  the payload together with a policy of its own: `default-src 'none'`, a per-response
  nonce for the single submit script, and `form-action` naming only the ACS this assertion
  is addressed to — taken from the registration, never from the request. The submit moved
  from a `body onload` handler to a script tag because an event-handler attribute can only
  be permitted by `'unsafe-inline'`, which is all-or-nothing for the whole document. Hosts
  with no policy are unaffected; `toPostForm()` still returns the same HTML.
- **Two migrations dropped a uniqueness constraint before adding its replacement.** MySQL
  DDL is not transactional, so a failure between the two statements is a state, not a
  rollback — and in that state DPoP proof-JTI replay and SAML assertion replay were
  unconstrained, on the two tables that exist to prevent exactly that, with the migration
  unrecorded so the deploy that would repair it could not run either. Both now add first
  and drop second, so the window holds two constraints instead of none.

## [0.77.1] - 2026-08-02

### Fixed

- **0.77.0's `saml_idp_sessions` table could not be created on MySQL or MariaDB, and left
  the schema stuck.** The Single Logout lookup was indexed over the raw
  `(environment_id, sp_entity_id, name_id)` triple. Two 512-character URI columns are
  4096 bytes in `utf8mb4` before the environment id is added, and InnoDB refuses a key
  over 3072 — so `create table` succeeded, the `add index` behind it failed, and the
  migration was never recorded. Every subsequent deploy then failed on *table already
  exists* without reaching the migrations queued behind it. The lookup is now a
  `lookup_hash` column — sha256 of the EntityID and NameID, NUL-separated so the boundary
  between them cannot be shifted — maintained by the model, and the migration drops the
  stranded table before recreating it. That drop can only fire where the migration is
  unrecorded, which is exactly the failed state; where 0.77.0 completed (sqlite,
  PostgreSQL) it is never called again. Upgrading from 0.77.0 needs no manual step.
- **A migration stranded by a half-applied run is now a covered case, not a discovery.**
  `tests/Migrations/MigrationRollbackTest.php` plants a table under a migration's name,
  leaves it unrecorded, and requires the migrator to run over it and leave the corrected
  schema behind. It runs on every engine the suite is pointed at, MySQL and MariaDB
  included — where DDL is not transactional and this failure shape is possible at all.

## [0.77.0] - 2026-08-02

> **Withdrawn 2026-08-02.** This release cannot be installed on MySQL or MariaDB: the
> `saml_idp_sessions` migration below builds an index InnoDB refuses, which leaves the
> table created, the migration unrecorded, and every later deploy stopping on *table
> already exists*. Use 0.77.1. Appended per the immutability note above — nothing in the
> entry itself has been altered.


### Security

- **Any registered service provider could log out any subject in the environment.** Single
  Logout took the NameID from a signed `LogoutRequest`, resolved it as a subject id OR an
  email, and revoked every session that person had — anywhere. A NameID is not a secret;
  for the default `emailAddress` format it IS the person's email address. So an SP an
  administrator had added for one purpose held a logout primitive over users it had never
  seen, usable repeatedly.

  Assertions are now recorded as they are issued (`saml_idp_sessions`: environment, SP
  EntityID, subject, NameID, SessionIndex), and SLO resolves the NameID **through the SP
  that presented it**. Only a subject we actually issued an assertion to, for that SP,
  under that name, can be logged out by it. An unresolvable NameID is a silent no-op — a
  logout that does not happen is a nuisance; one that happens to the wrong person is an
  outage.

  The `SessionIndex` was already minted into every assertion's `AuthnStatement` and thrown
  away. Recording it is what will let a conformant SP end one session rather than all of
  them.

### Fixed

- **A role orphaned after its mapping existed aborted the whole directory reconcile.**
  0.75.0 made `assertAssignableIn()` refuse orphaned roles but left `assignableOnly()` —
  the pre-filter whose entire job is to drop unresolvable ids *rather than let `assign()`
  throw* — matching the old predicate. The two diverged, and `assertAssignableIn()` throws
  `UnknownRole`, which the `GrantRefused` catch does not cover.

  This is the ordinary manifest lifecycle, not an attack: an app drops a role, the sync
  flags it, the mapping row survives by design. The next reconcile then aborted on the
  first member of that group — so the **revocation** pass never ran and a user removed
  upstream kept the role indefinitely — and because listeners run in registration order
  with access control ahead of webhooks and provisioning, every downstream listener was
  skipped on each attempt until the event dead-lettered. My regression; found by
  re-reviewing the change.

## [0.76.0] - 2026-08-01

Four SCIM defects, all of them silent — the connector sees a 200 and never retries, so
the directory and the downstream app diverge with nothing to reconcile them.

### Fixed

- **`members[value eq "x"].display` emptied the group.** The path addresses a
  sub-attribute of one member, passed the `members` prefix check, and arrived at
  `sync(valueIds("Some Name"))` — and `valueIds()` of a plain string is the empty array,
  so the branch that reads like "rename a member" detached every one of them. Refused
  rather than guessed at: this server stores no per-membership display value.

- **A pathless `replace` naming both a displayName and members applied only the rename.**
  A pathless operation carries the whole resource, so it means both; the rename branch
  fired first and returned, discarding the membership with a 200. Half an operation
  reported as all of it is worse than a refusal.

- **An outbound profile push wiped `givenName` and `familyName`.** RFC 7644 §3.5.2.3
  makes a pathed `replace` of a complex attribute a whole-attribute replacement, and the
  push emitted `{"op":"replace","path":"name","value":{"formatted":"…"}}`. Leaf paths
  (`name.formatted`) now replace one sub-attribute and leave its siblings alone. This is
  the same bug the INBOUND side found and fixed, never mirrored outbound — and its comment
  there explains that Entra's read-modify-write reconciliation pushes the omission back
  over the stored values on the next cycle. A multi-valued attribute like `emails` is
  still replaced whole, or a push could never remove an address.

- **A rotated downstream bearer token dead-lettered every queued operation.** 401 and 403
  were terminal, so a connection fixable in thirty seconds by pasting a new token had
  nothing left to retry by the time anyone did. Unlike the OAuth path, which refreshes
  with an expiry margin, a static bearer gives no warning it has been replaced. Retrying
  a genuinely revoked credential costs a bounded number of identical failures; dead-
  lettering a rotated one costs a silent, unrecoverable divergence.

## [0.75.0] - 2026-08-01

### Security

- **A role its declaring app had retired was still grantable.** Orphaning keeps the row
  and its existing assignments — deleting them would revoke access on a deploy blip — and
  the console stops offering the role. But `assign()` did not refuse it, so an
  administrator who knew a retired role's id could map a directory group to it by calling
  the action directly, and every reconcile then granted a role the owning application no
  longer believes in: carried in tokens, understood by nothing the app ships. A role that
  has vanished from the UI is exactly the one someone would name by hand.

  `assertAssignableIn()` now refuses an orphaned role, so the console's narrower rule and
  the framework's chokepoint agree. Re-declaring the role in a manifest makes it grantable
  again, so this tracks the manifest rather than being a one-way door.

## [0.74.0] - 2026-08-01

### Security

- **A SAML assertion naming no audience was accepted.** php-saml checks the audience only
  when one is PRESENT — `if (!empty($validAudiences))` — and nothing here re-checked it,
  while SAML 2.0 Profiles §4.1.4.2 makes it a MUST that the SP verify an
  `<AudienceRestriction>` exists and names it. Where an IdP can be made to emit
  audience-less assertions (Shibboleth and Keycloak custom mappers, a blanked Okta
  audience), an assertion that IdP legitimately minted for a DIFFERENT relying party was
  accepted here as a login. `InResponseTo` covers the solicited path, so the exposure was
  a connection with IdP-initiated sign-in enabled — the configuration with no other
  binding between request and response. Absent and wrong are now refused alike.

- **CIBA accepted public clients.** `authenticate()` admits a public client on `client_id`
  alone, which is safe where a front channel and PKCE bind the flow to the browser that
  started it. CIBA has neither, and its only human check is the approval prompt it puts on
  someone's phone — so a public `client_id`, which is not a secret and ships in every copy
  of an app binary, was enough to spray prompts at arbitrary users via `login_hint`. That
  attacks precisely the human-in-the-loop CIBA exists for: a person who has dismissed
  thirty prompts approves the thirty-first.

### Fixed

- **`client_credentials` answered 200 when it granted nothing.** Down-scoping a request to
  what a client registered for is deliberate and correct — §5.1 permits a granted set that
  differs from the request provided the response says so, and it does. But §5.1's ABNF has
  no empty production for `scope`, so when NOTHING survived the filter the echo could not
  be sent and the response was indistinguishable from "you got everything you asked for".
  A request where nothing survives is a refusal, and §5.2 has the error for it. The
  partial-grant behaviour is unchanged and now pinned by its own test.

### Testing

- **Three outbound federation SSRF sites had no test at all** — OIDC discovery, JWKS fetch
  and SAML metadata import. `pinnedOptions()` is the only protection on those paths. That
  absence is not theoretical: the equivalent pin on the outbound SCIM client was replaced
  with an empty array during this review's own falsification work, swept into a commit and
  released, and every suite stayed green. Each is now armed with `Http::fake` on the
  blocked address, so a bypass SUCCEEDS visibly rather than erroring on an unreachable
  network.

- **`--group=isolation` contained 34 tests when 149 belonged in it.** Pest ignores a
  file-level `@group` docblock — membership comes from `uses()` or a per-test `->group()`
  — so seventeen files that declared it contributed nothing, including
  `EnvironmentIsolationTest` itself. `docs/core-concepts/environments.md` tells operators
  to run exactly that command as the evidence that tenants are separated, so someone ran
  it, saw green, and drew a conclusion about the wrong 34. A meta-test now fails if a file
  claims the group without joining it.

## [0.73.0] - 2026-08-01

### Added

- **`Subjects::update()`** — change a subject's name and/or email, audited as
  `user.updated` and emitted as a domain event. There was no verb for this, so the host
  console reached past the contract and called `$user->save()` on the model: the only
  direct model write left in it, while every neighbouring action went through a contract.

  Three things followed. No audit record for the most security-relevant mutable attribute
  on an account — email is both the primary identifier and the recovery channel.
  `user.updated` offered in the console's webhook picker with nothing anywhere emitting
  it, so subscribers got silence. And the outbound SCIM path's `'user.updated' => Upsert`
  branch permanently dead, so a legal name change propagated to no downstream application,
  ever.

  A changed email lands **unverified**: an administrator asserting an address is not its
  owner proving one, and keeping the flag would make this an account-takeover primitive —
  set an address you control, and every recovery path points at you. A no-op update
  records nothing, because an access review reading "the email changed" when it did not is
  worse than silence.

## [0.72.0] - 2026-08-01

### Security

- **`POST /oauth/decisions` now pins the audience.** It accepted any active access token
  and checked neither the audience nor a scope, while answering with strictly more than
  UserInfo does — the subject's entire permission and entitlement set in the organization.
  UserInfo has refused a wrong-audience token for some time, with a docblock explaining
  that a token minted for a specific RFC 8707 resource must not be replayable to harvest
  identity claims; the same reasoning applies here with more at stake.

  Concretely: an organization registers an app with `resource=https://app-a.example`.
  Anyone holding a token audienced to that app — the app, or whoever compromises it —
  could replay it here and enumerate that user's whole authorization surface. UserInfo
  says no to the identical token.

### Added

- **`cbox-id.oauth.decisions.require_scope`** (`CBOX_ID_OAUTH_DECISIONS_REQUIRE_SCOPE`),
  requiring `decisions:read` on the presented token. **Off by default**, because the
  endpoint has always accepted any active token and turning this on unannounced refuses
  every integration that has not been updated to ask for the scope. The audience check
  above is not optional and is always enforced.

### Fixed

- **The endpoint's three distinct 401s are distinguishable.** No token, an inactive token
  and a failed DPoP proof all emitted the same bare `{"error":"invalid_token"}`, two of
  them with no `WWW-Authenticate` at all — which RFC 6750 §3 makes a MUST, and which
  `TokenController` had already solved one file over, noting that several real client
  libraries treat a bare 401 as fatal. Each now carries its own `error_description` and a
  challenge header.

## [0.71.0] - 2026-08-01

### Security

- **Segregation of duties now runs at the grant chokepoint, not in front of it.** The rule
  was correct and was only ever asked on the paths a host can intercept — the console's
  four manual grant paths. Directory group→role mappings are reconciled INSIDE the
  framework, so a user added to two upstream groups received the forbidden pair silently
  on the next reconcile: the automation a customer buys was the way around the control
  they bought. `RoleService::assign()` already called itself "the chokepoint every caller
  funnels through", and it was — for ownership only.

  Enforced through a new `AccessControl\Contracts\GrantGuard` rather than a direct
  dependency, because `Governance` already depends on `AccessControl` and pointing it back
  would close a module cycle. The default binding permits everything; `Governance` replaces
  it, so loading governance is what turns the gate on. A vetoed directory grant is skipped
  and audited as `role.grant_withheld` rather than aborting the reconcile — one person's
  conflicting membership must not abandon everyone else's sync.

  Note the consequence for the detective control: `scan()` still matters, because a
  violation can now only arise from a policy defined AFTER the roles were held, which is
  the ordinary way rules get written.

- **One TOTP code or recovery code admitted two sign-ins under a race on the operator and
  account-member planes.** Both did a read-then-write; the subject plane has used a
  conditional UPDATE from the start, with a comment explaining that two requests
  presenting the same intercepted code both pass the replay check. `DatabaseOperatorMfa`'s
  own docblock claimed the planes could not drift on the security-relevant parts. Both now
  consume with a conditional update and return whether they won it.

- **SCIM Group `PATCH` with no `path` emptied the group and answered 200.** RFC 7644
  §3.5.2.2 requires 400 with `scimType: noTarget`, which `/Users` has always answered and
  `docs/security/standards.md` already claimed for both. A connector that dropped `path`
  on a membership reconcile therefore detached every member, recorded a success, and never
  retried — and because membership drives the group→role bridge, every mapped role went
  with it.

### Changed

- **`Mfa::disable()` takes an optional actor.** It hardcoded the subject, so an
  administrator removing someone's second factor was recorded as that person doing it
  themselves — erasing the one distinction the verb was added to capture. Defaults to
  self-service, so existing callers are unaffected.

## [0.70.0] - 2026-08-01

### Security

**Restores two controls that 0.68.0 and 0.69.0 shipped without.** Both were deleted by
accident, not by decision, and both were released. Those two versions have since been
**withdrawn** — their tags are deleted, so neither can be installed. Earlier versions
are unaffected.

- **The SAML digest-algorithm pin was removed**, leaving an empty loop where the check
  had been. A response signed RSA-SHA256 but digested with SHA-1 was accepted — the
  signature pin still held, so only the weaker half of the pair was open.

- **The outbound SCIM client's SSRF pinning was replaced with an empty option set**, so
  delivery-time DNS pinning was off. Registration-time validation still applied, which
  means the exposure was specifically the rebind window: a host that resolves publicly
  when a connection is registered and privately when an operation is delivered.

How it happened, because the mechanism matters more than the diff: both edits were
falsification probes from this review's own testing pass — deliberate deletions made to
check whether a guard was actually guarded. They were still in the working tree when a
`git add -A` swept them into an unrelated commit. Neither test suite went red, because
neither control had a test that failed when it was deleted, which was the very finding
the probes were confirming.

### Testing

- **A mixed-algorithm SAML response** — RSA-SHA256 signature, SHA-1 digest. Every existing
  SAML test used an all-SHA-1 document, which trips the signature pin first, so the digest
  pin was never the reason any test passed and could be deleted in silence. The fixture's
  single `sha1` flag now splits in two so the two pins can be exercised apart.

- **Delivery-time SSRF refusal on the outbound SCIM client**, which had no test at all.
  The connection is registered with the guard off and the guard enabled for the delivery,
  so it proves the delivery-time check specifically rather than the registration one.

## [0.69.0] - 2026-08-01

> **Withdrawn 2026-08-01.** The tag for this version was deleted, so it can no longer be
> installed. It shipped without the SAML digest-algorithm pin and without the outbound
> SCIM client's delivery-time SSRF pinning — see [0.70.0](#0700---2026-08-01) for what was
> removed, how, and what now proves it cannot happen unnoticed again. The entry below is
> left as written, because a changelog that quietly loses a version is worse than one that
> records a withdrawn one.


No behaviour change. Two guards that did not guard, found by deleting the code they
claim to protect and watching the suite stay green.

### Testing

- **The SAML XML-Signature-Wrapping test proved nothing.** Making both binding checks in
  `EmbeddedSignature` return unconditionally left all 19 tests passing. The wrapper the
  test built omitted `Destination`, so the parser rejected it at an unrelated check long
  before the binding checks ran — and since `InvalidAuthnRequest` is the single exception
  class for every rejection reason, asserting only the class could not tell the two
  apart.

  What was unguarded: an SP whose certificate we trust lifting its own valid signature
  onto an `AuthnRequest` root it controls, and the IdP treating it as authentic. That is
  SP impersonation on the IdP's front door.

  Now three cases, each asserting the MESSAGE: signature at the root referencing the
  decoy, signature buried below the root, and two signatures on the root. Each binding
  check falsified independently.

- **Nine of the eleven fields in the audit-chain hash were not proven to be in it.**
  Only `action` and `environment_id` had a tamper test. Removing `actor_type`,
  `actor_id`, `target_type`, `target_id`, `context`, `ip` and `recorded_at` from
  `canonicalPayload()` left the Audit, AuditQuery, AuditStreaming and Maintenance suites
  green — so a refactor could drop WHO acted, FROM WHERE, ON WHAT and WITH WHAT DETAIL
  out of the hash, and anyone with database write access could rewrite all four while
  `verifyChain()` still answered "valid". In the one subsystem whose entire product claim
  is tamper-evidence.

  Now one case per column. `environment_id` and `scope` break at the FOLLOWING entry
  rather than the tampered one, because they identify the chain — rewriting either
  removes the row from the chain being read instead of corrupting it in place, which is
  the property that makes a row unmovable between environments.

## [0.68.0] - 2026-08-01

> **Withdrawn 2026-08-01.** The tag for this version was deleted, so it can no longer be
> installed. It shipped without the SAML digest-algorithm pin and without the outbound
> SCIM client's delivery-time SSRF pinning — see [0.70.0](#0700---2026-08-01) for what was
> removed, how, and what now proves it cannot happen unnoticed again. The entry below is
> left as written, because a changelog that quietly loses a version is worse than one that
> records a withdrawn one.


### Changed

- **`AuthPolicies` gained `overridesFor()`** — every organization's override in one read,
  keyed by id, omitting the ones with none. Breaking for a host that implements the
  contract itself; [`UPGRADING.md`](UPGRADING.md) carries a working fallback.

  Memoising `overrideFor()` in 0.67.0 removed the DUPLICATE reads — two per organization
  down to one — but left the shape untouched: a subject in nine organizations still cost
  nine queries on every authenticated request, and the Sign-in rules console page pays it
  once per organization in the whole environment, unpaginated. Absences are memoised as
  well as hits, because a subject with no overrides would otherwise re-read every one of
  their organizations next request — the exact cost this replaces.
  `DatabasePasswordExpiry` and `DatabaseMfaMandate` both use it.

### Testing

- Proven at twelve organizations, half with an override and half without: one query cold,
  none warm.

## [0.67.0] - 2026-08-01

Found in the sixth whole-platform review loop. One of these is a shared-fate performance
ceiling rather than a security bug, and it is the more urgent of the two.

### Fixed

- **Every authenticated request scanned every tenant's memberships.** `memberships` was
  created with indexes on `environment_id` and `organization_id` plus
  `unique(organization_id, user_id)`. `user_id` is the SECOND column of that unique, and
  no composite index can serve a predicate on its second column alone — so a lookup by
  `user_id` had nothing at all. That would be a footnote if the query were rare;
  `MembershipService::forUser()` runs `withoutScope` by design, so the SQL carries no
  environment filter either, and the host calls it from its authentication middleware on
  every request. One customer's page load therefore got slower as OTHER customers signed
  up. Indexed as `(user_id, created_at, id)`, which answers the sort as well as the
  filter.

- **`DatabaseAuthPolicies::overrideFor()` was the one policy read not memoised**, and the
  one called in a loop: `PasswordExpiry` and `MfaMandate` both walk the signed-in
  subject's memberships asking for each organization's override, from that same
  middleware. Measured on a console page before the fix: 17 queries at one organization,
  22 at four, 32 at nine — exactly two per organization, on every request. Now memoised
  per request, keyed by environment AND organization for the same reason
  `forEnvironment()` is, and cleared on every write.

### Testing

- The membership index is proven two ways: the sqlite query plan names it, and an
  engine-independent assertion checks it exists — the second is what runs on the Postgres
  and MySQL legs, where the plan syntax differs.
- The memo is proven by measuring from WARM and asserting zero further reads, rather than
  pinning a query count that would stop meaning anything the moment an unrelated read was
  added. Its invalidation and its environment keying are separately falsified.

## [0.66.0] - 2026-08-01

Found during a whole-platform review. Two of these are cross-tenant defects on the
sign-in path, and one is a migration blocker that presented as "wrong password".

### Fixed

- **`$2a$` and `$2b$` bcrypt hashes were rejected as if the password were wrong.**
  `NativePasswordVerifier::supports()` decided a hash was native by asking
  `password_get_info()`, which only ever recognizes what `password_hash()` EMITS — on
  PHP 8 that is `$2y$` alone, and it answers `algo: null` for `$2a$` and `$2b$`.
  Because the verifier is deny-by-default, every hash exported by a provider that
  writes those prefixes — most of them — failed authentication as an ordinary bad
  password. A customer migrating onto the platform would have watched their entire
  user base locked out, with nothing in any log saying why. `password_verify()` had
  handled all three correctly the whole time; only the gate in front of it was wrong.
  The class docblock had promised this support since it was written, so the claim was
  never true. Now proven against the canonical crypt_blowfish vectors rather than
  against hashes this process made itself.

- **A SAML assertion ID consumed by one tenant blocked every other tenant's.**
  `consumed_assertions.assertion_id` carried a GLOBAL unique index, but an assertion
  ID is chosen by the issuing identity provider and is only required to be unique
  within it — short and sequential IDs are common in the wild. Two customers' IdPs
  minting the same ID meant the second one's perfectly valid login was refused as
  "assertion replay detected": a cross-tenant denial of service on sign-in, and a
  targetable one. The replay key is now `(environment, connection, assertion id)` —
  single-use per issuing IdP, which is what the guard was ever defending. Same
  correction as `unique(jti)` on the DPoP table in 0.61.0, for the same reason.

- **Domain capture could be enabled on a domain nobody had proved they own.**
  `DomainVerification::setCapture()` left the verification check to its callers, and
  the callers disagreed — one console refused an unverified domain, the other did not,
  so the weaker of the two decided the rule. Capture routes every sign-in on an email
  domain to one organization's connection, so on an unverified domain it is one tenant
  claiming another's addresses. The check now lives in the service, where nothing can
  route around it. Disabling capture stays unconditional: withdrawing a claim is
  always safe.

### Added

- **`Mfa::disable()`** on the subject plane, audited as `user.mfa_disabled` — the same
  shape the account and operator planes have recorded from the start. Without this
  verb, an administrator resetting a second factor for someone who lost their
  authenticator had to delete the rows directly, so the single most privileged MFA
  mutation in the platform was the only one that left no trail. Every other MFA
  mutation was already audited.

- **`DomainNotVerified`**, thrown by `setCapture()`. Hosts that surface federation
  settings should catch it and show the DNS challenge rather than a generic failure.

### Testing

- **Frozen envelope vectors for `LibsodiumSecretBox`.** Every prior test sealed and
  opened in the same process, which moves both sides together: change the nonce
  length, add a version byte, swap base64url for base64, and a round-trip still passes
  while every secret already at rest becomes permanently unreadable. This box seals
  private signing keys, directory credentials and vault secrets. Two checked-in
  ciphertexts now pin the envelope format, so breaking it is a migration rather than a
  silent refactor.

- **Foreign password hashes** — the canonical openwall `$2a$` vectors, a `$2b$` hash,
  and argon2i/argon2id hashes generated out-of-process. These are what caught the
  bcrypt bug above; the previous coverage could only ever produce `$2y$`.

## [0.65.0] - 2026-07-27

### Removed

- **`EntitlementSource::License`.** The framework never wrote it; it existed so
  `cboxdk/laravel-id-licensing` could mark entitlements unlocked by a signed offline
  key. That layer is retired — the application this framework backs is now free to
  self-host with no key and no limits, so a source meaning "granted by a licence" has
  nothing left to mean. The on-prem licensing entry is gone from the docs for the same
  reason.

  A `license` value stored by a real licensed deployment will no longer hydrate. See
  [`UPGRADING.md`](UPGRADING.md).

## [0.64.0] - 2026-07-27

### Fixed

- **The audit chain's first entry deadlocked on MariaDB.** Appending serialises on the
  chain's anchor (sequence 1); on an *empty* chain there is none, and the locking read
  looking for it matched no row — which InnoDB answers with a **gap lock**. Eight
  processes opening one brand-new chain each held that gap and then needed an
  insert-intention lock inside it, so MariaDB 11.8 resolved the pile-up as SQLSTATE 40001
  rather than the duplicate key `record()` is written to absorb, and `attempts: 3` ran
  out. **6 of 800 appends lost.** Fixed by removing the cause rather than raising the
  budget: the anchor is now *found* with a plain read and *locked by primary key*, and an
  exact primary-key match takes a record lock that can never be a gap lock — so an empty
  chain takes no lock at all. The search runs **outside** the transaction, because under
  `REPEATABLE READ` a consistent read inside it fixes the snapshot the head read is then
  answered from; an earlier attempt that kept it inside made things strictly worse. Now
  **800/800 on `mariadb:11`**, and the full suite runs green there for the first time.
- **CI's rollback step never rolled anything back.** Testbench's rollback is `--path`-
  scoped to a single publishable migration, so 83 tables and 90 ledger rows survived it on
  an empty PostgreSQL, and `down()` was unverified on every engine. The replacement
  migrates every registered path into a throwaway database, resets across all of them, and
  requires **zero** tables and **zero** ledger rows before migrating back up. The assertion
  is the point — a rollback that does not verify emptiness is exactly how this went
  unnoticed. It found **five** broken `down()` methods, the worst of which left a stray
  `password_reset_tokens` behind after a full reset, under the very name whose collision
  with Laravel's skeleton migration breaks a greenfield install.

### Added

- **Audit checkpointing is schedulable** — `php artisan cbox-id:audit:checkpoint` signs
  every `(environment, scope)` chain that has advanced, idempotently and without locking.
  Nothing had ever scheduled `checkpoint()`, so `audit_checkpoints` was empty everywhere
  and `verifyCheckpointAnchor()` returned null on every call: the chain detects
  modification and sequence gaps by itself, but it cannot detect **truncation**, and a
  signed checkpoint is the only thing that catches that.
- **The schedule defaults to `false`, deliberately.** The GDPR-erasure design still to come
  needs exactly one *re-chain* of existing rows — hashing ciphertext instead of plaintext,
  so destroying a per-subject key leaves every hashed byte unchanged. Any checkpoint signed
  *before* that would afterwards report tampering that never happened, permanently, on
  evidence you may already have handed to a third party. Nothing has ever signed one, so
  the window is open and **the first signature closes it**. `UPGRADING.md` carries the
  four-step order — and says plainly that a deployment with no re-chain ahead of it should
  turn this on today rather than run an audit trail whose truncation nobody would notice.
- `OrganizationStatus::revokesAccess()`. The enum now answers the question the security
  layer was asking by hand, with an exhaustive `match` and no `default`, so a status added
  later fails static analysis instead of defaulting to "allowed" — which is precisely how
  `Deleted` slipped past three enforcement points in the consuming app.
- `Organizations::archive(string $id, string $actorId)`, so the status write and its audit
  entry both live behind the contract instead of a raw `save()` in a console view.

### Changed

- **BREAKING:** `Accounts::suspend()` and `Accounts::reactivate()` now take an `$actorId`
  and audit internally, matching `Organizations` and `PlatformOperators`. They previously
  took an id alone and recorded nothing, which forced every caller to remember the audit —
  and a second caller would have silently forgotten it. `reactivate()` is included even
  though only `suspend()` was reported: leaving it unaudited would make "who lifted this
  suspension" unanswerable directly beside an audited suspend.

## [0.63.0] - 2026-07-27

### Security

- **`POST /user-tokens/introspect` checked no scope at all.** It resolved the caller's
  environment API key and verified only that it was *valid*, while every other management
  route gates on a scope. A key issued with, say, only `directories:read` could introspect
  **every personal access token in the environment** and read back `sub`, `org`, `name`
  and `scope` — a deliberately narrow credential holding a capability it was never
  granted. Now gated on the existing `EnvironmentApiScope::UsersRead`: a successful
  response discloses user data about any user in the environment, which is exactly what
  `GET /users` already gates on, so minting an `introspect:*` scope would have added scope
  surface for a capability an existing scope already describes — and would have broken
  every key rather than only those that genuinely lacked user-read rights.
  **BREAKING:** an environment API key calling this endpoint without `users:read` now gets
  `403 insufficient_scope`. Audit issued keys before upgrading. The refusal is a 403 and
  not `active: false` deliberately: it is decided *before* the token is resolved, so the
  response is a constant function of the caller's own key and leaks nothing about any
  token — whereas answering `active: false` would make a relying party silently treat
  every live credential its users hold as revoked, reading a misconfiguration as a
  fleet-wide revocation. A test pins that the 403 is byte-identical for a known and an
  unknown token, so it cannot become an oracle by accident later.
- **An empty resource-family allow-list granted every family.** `UserApiTokenService`
  stored `$families === [] ? null : $families`, and `allowsFamily()` reads `null` as
  "unrestricted" — so a caller passing an **empty** allow-list, the most restrictive input
  possible, received a token permitted on **all** families. The most restrictive request
  produced the least restrictive result. Fixed with a `ResourceFamilies` value object that
  keeps *unrestricted*, *a list*, and *none* apart; the collapsing line is gone because
  `[]` is no longer a value the parameter can hold. An array cannot express the difference
  between absent and empty, and here that difference is a security boundary. Existing rows
  are untouched — `NULL` still means unrestricted, and the empty array is a value the old
  code could never write. The wire format is unchanged.
  **BREAKING (source-level):** `UserApiTokens::issue()` now takes `?ResourceFamilies`
  instead of `?array`.

### Fixed

- **A greenfield install could not migrate.** The package created `password_reset_tokens`,
  which Laravel's own `create_users_table` skeleton migration — present in every freshly
  scaffolded app — also creates, with a different shape. So `composer require
  cboxdk/laravel-id && php artisan migrate` failed with "table already exists" on every
  engine: the package's entire first-run experience for anyone who did not start from a
  stripped skeleton. Renamed to `cbox_id_password_reset_tokens`, with a rename migration
  guarded three ways — it returns early if the new name exists, if the old one does not, or
  if the table it finds lacks `environment_id` **and** `token_hash`. Laravel's skeleton
  table has neither, so this migration can never adopt, reshape or drop a table it did not
  create. The suite could not have caught this: the harness publishes the package's own
  users migration, so no test had ever migrated against a stock Laravel schema.
  `GreenfieldMigrationTest` now does, on SQLite and against a throwaway schema on a real
  PostgreSQL server.

### Added

- **A verified capability matrix** — a "What's supported" table in `README.md` and a new
  `docs/capabilities/` section, so an adopter can answer "do you support X?" in seconds.
  Five grades defined at the top of every table, and `docs/security/standards.md` becomes
  the canonical RFC/protocol matrix. Every row was checked against `src/` rather than
  written from the existing docs — which disproved eleven claims, corrected below.

### Changed

- **Documentation claims that the code does not back have been corrected.** The matrix
  above was built by verification, and these are what it found:
  `compliance.md` offered *signed commits* as the SOC 2 CC8.1 control (`git log
  --format=%G?` returns `N` for every commit, releases included); the GDPR Art. 17 claim
  survived an earlier rewording and was still false, since no erasure primitive exists and
  the package holds contact PII in its own never-pruned tables; `fapi.md` claimed PAR was
  *enforced* (`require_par` is read in exactly one place — building the discovery
  document) and RFC 9207 `iss` *always on* (the package emits no authorization response);
  step-up "sudo" re-authentication was claimed as a mitigation in four control rows and
  does not exist; and `standards.md` described `/authorize` behaviour throughout —
  **this package does not serve `/authorize`**, and was claiming the host app's work as
  its own. Password policy had moved into the framework several releases ago and was still
  attributed to the app layer; under-claiming is a documentation bug too.
- `TotpAuthenticator`'s docblock cited **RFC 4238** for HOTP. HOTP is **RFC 4226**.
- The SCIM `ServiceProviderConfig` advertised `documentationUri` as `<app>/docs`, a route
  this package does not register and most hosts do not either — so a connector surfacing
  that link during setup sent the operator to a 404. It is OPTIONAL in RFC 7643 §5 and is
  now omitted unless `cbox-id.scim.documentation_uri` is set.
- `Directories::resolveByToken()` promised a constant-time comparison the implementation
  never performed.
- `UPGRADING.md` carried the last surviving copy of the fabricated
  `urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified`. No such value exists — SAML 2.0
  carries the 1.1 URN forward, and `tryFromPolicyUrn()` returns null for the 2.0 spelling,
  so an SP configured from that line is answered `InvalidNameIDPolicy`.

## [0.62.0] - 2026-07-27

### Fixed

- **PostgreSQL handed every short identifier back to PHP blank-padded, and the whole
  platform mis-compared it.** `$table->ulid($column)` is `$table->char($column, 26)`,
  and PostgreSQL implements `CHAR` as `bpchar` — blank-padded — so a value shorter than
  the declared width is stored padded and PDO passes the padding straight through.
  `$row->environment_id === 'env_test'` was therefore **false** for a row whose
  `environment_id` is `env_test`. It hid perfectly: Postgres' own `=` and `length()`
  strip trailing blanks, so every check from a SQL client passed, and real ULIDs are
  exactly 26 characters so nothing pads in a normal deployment. It cost **338 of 1358
  tests on postgres:16** — `BelongsToEnvironment` throwing `CrossEnvironmentAccess` on
  a row's own environment, and `DatabaseAuditLog::verifyChain()` reporting `content
  hash mismatch (tampered)` on an untouched chain because `canonicalPayload()` hashes
  `organization_id` unpadded at write and padded at read. All 225 identifier columns
  are `varchar` now: the create migrations say `string($column, 26)`, and
  `2026_07_26_000100_convert_char_columns_to_varchar` converts an existing database
  (casting `bpchar` to `varchar` strips the padding already on disk, so no backfill is
  needed). Verified by diffing `pg_dump --schema-only` of an upgraded v0.61.0 database
  against a fresh install: zero difference, indexes and foreign keys intact under their
  original names. See `UPGRADING.md` for locking, sizing and rollout order.
- **Membership rosters were not totally ordered, so a page could start in the middle.**
  `MembershipService::paginateForOrganization()` sorted on `created_at` alone — a
  second-granularity timestamp that ties across every row of a roster built in one
  request. `ORDER BY` a tied key promises nothing, and under `LIMIT`/`OFFSET` it lets a
  row appear on two pages or on none; PostgreSQL's top-N heapsort made it visible by
  returning the second member first. Now ordered by `created_at` then `id` (a ULID, so
  the tie-break runs the same direction). A pre-existing defect that the padding bug
  above was masking — both fail the same test, and only the second one is left once the
  padding is fixed.

### Changed

- **CI runs the full test suite on PostgreSQL**, not just the migrations. The `engines`
  job promoted `postgres:16` from migrations-only now that the padding defect above is
  fixed and the cell is green — 1359 passed, measured twice, against a real
  PostgreSQL 16. MySQL 8 also lands 1359, and SQLite 1358 passed with 1 skipped.
  MariaDB stays migrations-only for the first-append deadlock documented in
  `docs/requirements.md`; its failure count is carried forward from v0.61.0 rather
  than re-measured.
- **`tests/Feature/SchemaPortabilityTest.php` fails the build if a `CHAR` column
  helper reappears** in a migration — `char()`, `ulid()`, `uuid()`, `foreignUlid()`,
  `ulidMorphs()` and friends. It is a token scan rather than a schema assertion so it
  runs on SQLite, catching the mistake on a contributor's first local run instead of in
  the server-engine job.
- **`docs/requirements.md` no longer claims the migrations are tested in both
  directions.** The `Migrations up` CI step does not roll back: measured on
  `postgres:16` against an empty database, 83 tables and 90 rows in `migrations` remain
  when it finishes, on this commit and on v0.61.0 alike. Testbench's rollback is scoped
  by `--path` to the one publishable migration the TestCase loads directly. The step is
  renamed and the docs corrected; making it real is separate work.

## [0.61.0] - 2026-07-27

### Fixed

- **The migrations could not run on MySQL or MariaDB at all**, while
  `docs/requirements.md` and the installation guide promised "any database Laravel
  supports — MySQL/MariaDB, PostgreSQL, SQLite, SQL Server". `php artisan migrate` died
  on the fifth table: twenty `json` columns across sixteen migrations carried a literal
  `DEFAULT '{}'` / `DEFAULT '[]'`, which MySQL has never allowed on a BLOB/TEXT/JSON
  column (error 1101 — since 8.0.13 it takes only the parenthesised *expression* form).
  Behind that were three more walls, each of which also stops the migration dead:
  `relationship_tuples` and `vault_secrets` had composite indexes over InnoDB's
  3072-byte key limit (utf8mb4 charges 4 bytes per character, so seven `varchar(255)`
  columns is 6224), and two generated index names exceeded MySQL's 64-character
  identifier limit (error 1059). `json` defaults now go through
  `Cbox\Id\Kernel\Database\JsonDefault`, which emits `DEFAULT (json_object())` /
  `DEFAULT (json_array())` on MySQL and MariaDB and the **unchanged literal** on every
  other engine — the PostgreSQL and SQLite DDL is byte-identical to before. Columns
  inside the over-long indexes were given explicit lengths and three index names were
  shortened; see `UPGRADING.md` for the exact list and why no `ALTER` is shipped.
- **Three index names were over PostgreSQL's 63-character identifier limit** and were
  being silently truncated, so the same index carried a different name depending on the
  engine. All three are now named explicitly.
- `InteractsWithFederation::fakeDns()` tripped static analysis at level max after a
  dependency update taught larastan to infer `app(DnsResolver::class)` from the container
  *binding* — from which it concluded the concrete resolver is the only possible result
  and the `FakeDnsResolver` short-circuit is unreachable. Rebinding that contract is
  exactly what the method does, so the inference was wrong about runtime rather than the
  code being wrong. Resolved through the PSR-11 `get()` accessor, which returns `mixed`
  and lets the `instanceof` mean what it says — rather than silencing the check.

### Added

- **CI runs against real database servers.** A new `engines` job migrates forwards and
  back against `mysql:8`, `mariadb:11` and `postgres:16` service containers, and runs
  the full suite on MySQL (1358 passed, against MySQL 8.4). Running only on sqlite —
  which accepts literal json defaults and caps neither index keys nor identifiers — is
  precisely why the MySQL claim went sixty releases without anyone noticing it was
  false.
- The MariaDB and PostgreSQL cells run **migrations only**, and the job says why in
  full. Adding it surfaced two pre-existing product defects that stop the suite passing
  there, neither of them a schema problem:
  - PostgreSQL: `$table->ulid()` is `char(26)`, PostgreSQL blank-pads `CHAR` on read
    where MySQL and SQLite strip it, so every environment key shorter than 26
    characters fails the tenancy guard (`row belongs to [env_test⎵⎵⎵…], acting as
    [env_test]`) — 338 of 1358 tests. Invisible in production because a real
    environment id *is* a 26-character ULID.
  - MariaDB: eight processes appending to an **empty** audit chain deadlock on the gap
    lock the `FOR UPDATE` takes where the anchor row does not exist yet. MariaDB raises
    SQLSTATE 40001 rather than the duplicate key `DatabaseAuditLog::record()` absorbs,
    and `attempts: 3` is not enough for eight contenders: 6 of 800 appends failed —
    loudly, with an exception, not silently. The identical test lands 800/800 on
    MySQL 8.4.

### Changed

- **`docs/requirements.md` and the installation guide now state which engines are
  tested, not which are hoped for.** SQL Server was never run by anybody and is no
  longer claimed. MySQL's floor is documented as 8.0.13 and MariaDB's as 10.2, the
  releases that introduced expression column defaults.
- On a server driver (`DB_CONNECTION=mysql|mariadb|pgsql`) the suite now runs under
  `RefreshDatabase` — migrate once, then a transaction per test — instead of Testbench's
  migrate-and-roll-back-around-every-test. The sqlite default is unchanged. Rebuilding
  ~390 DDL statements per test costs over a minute a test on a real server, which would
  have made the job above unrunnable.

## [0.60.0] - 2026-07-27

### Fixed

- **Audit entries were silently lost whenever two writers appended to the same chain.**
  Appends serialised on the chain HEAD, chosen by `ORDER BY sequence DESC LIMIT 1 FOR
  UPDATE`. Under `READ COMMITTED` a blocked `FOR UPDATE` re-checks its predicate against
  the row it waited on, not against the `ORDER BY` that selected it — so a waiter woke
  still holding the old head, computed a sequence that had just been taken, and died on
  the unique key with SQLSTATE 23505. `DB::transaction(…, attempts: 3)` never covered it:
  Laravel's `ConcurrencyErrorDetector` matches 40001 and deadlock messages, not 23505.
  Measured on PostgreSQL 16, 8 processes × 100 appends to one chain landed **101 of 800**
  rows; it now lands 800 of 800, gapless, with `verifyChain()` valid. These writes sit on
  pre-authentication paths, so a credential-stuffing burst was the trigger, and callers
  that `report()` and continue lost their entry without a trace. Appenders now serialise
  on the chain's anchor row (sequence 1), whose predicate is an equality on the unique key
  and therefore cannot go stale. Costs one extra indexed round-trip: single-writer p50
  12.4 ms → 13.3 ms. The docblock claiming a concurrent write "is never silently lost" was
  false and has been replaced with the actual semantics.

### Changed

- **BREAKING (error paths only):** an append that cannot claim a free position within its
  retry budget now throws `CannotAppendToAuditChain` instead of surfacing the driver's
  `UniqueConstraintViolationException`. A hole in a tamper-evident trail is
  indistinguishable from a deletion when someone later runs `verifyChain()`, so it must be
  loud. Callers catching `QueryException` around `AuditLog::record()` should catch
  `CannotAppendToAuditChain` as well.

## [0.59.1] - 2026-07-27

### Added

- `HookPoint::label()` and `::description()`. A hook point is chosen by a human in a
  console, and without copy a view renders `$case->name` — so an admin picked between
  "PrePasswordChange" and "PostPasswordChange", PHP identifiers as product copy. Tolerable
  while there was one point; not with six. The copy lives on the enum rather than in a
  host's view because the enum is a public contract and every console would otherwise
  restate it. `description()` always says whether the hook can refuse, since that is the
  difference an admin needs before wiring a URL that can stop people signing in.

## [0.59.0] - 2026-07-27

### Added

- **Five new inline-hook points, so a host can gate more than token issuance.**
  `HookPoint` shipped exactly one point, `token_minting`, and the file's own comment
  admitted it. The pipeline underneath it was always generic, so the gap was call sites,
  not machinery. Added `post_login` (after authentication, before the session row is
  written — every login path, because it fires from `SessionManager::start()`),
  `pre_registration` / `post_registration` (around subject creation) and
  `pre_password_change` / `post_password_change` (around a credential write). Each has a
  typed payload value object under `ExternalActions\Payloads\`, so the wire shape lives
  somewhere a change to it is a reviewable edit rather than an array literal buried in a
  service. `ActionContext::for()` builds a context from one, and cannot mismatch the hook
  point with its payload.
- **A per-hook-point fail policy, because "fail closed" is not one answer.** A hook that
  is consulted and denies always denies — that is not configurable. A hook that could not
  be consulted at all now answers to `HookPoint::failPolicy()`: the gates
  (`token_minting`, `pre_registration`, `pre_password_change`) deny, because a control
  that fails open is not a control; `post_login` allows, because failing closed on the
  hottest path in the product hands one customer-controlled URL the power to lock a whole
  tenant out of everything, the admin console included. Override per point with
  `external_actions.fail_policy.<hook>`, or globally with `external_actions.fail_open`.
- **`docs/extension-points/hook-points.md`** — every point, its payload, what a deny
  stops, and what an unreachable endpoint means there.

### Changed

- **`external_actions.fail_open` now defaults to unset rather than `false`.** A literal
  `false` means "close every point", which would have overridden `post_login`'s
  deliberately open default. Unset lets each point's own default apply. Behaviour for
  `token_minting` is unchanged either way, since its default is closed.
- **A deny at a `post_*` hook point is audited and then folded to an allow.** Those points
  run after their operation has committed, so a veto has nothing to stop. Enforced in
  `DefaultActionPipeline` rather than trusting each call site to ignore the outcome; the
  `external_action.denied` audit entry carries `vetoable: false` so the operator still
  sees it.
- **`fakeActionTransport()` now also rebuilds the singletons that hold the pipeline**
  (`SessionManager`, `Subjects`, `TokenIssuer`), which otherwise kept calling the real
  transport through the instance they already had.

### Notes

- No separate `credentials_exchange` point was added. `token_minting` already fires on the
  `client_credentials` grant, with `user_id` null and `grant` set — a second point would
  be a second name for the same call, with a second endpoint to register and a second
  timeout to pay.
- The registration and password-change points carry no organization (neither operation
  has one), so only environment-level endpoints fire for them. `token_minting` and
  `post_login` are org-scoped as before.

## [0.58.0] - 2026-07-26

Typed-model debt from the platform review. **Two breaking contract changes** — see
`UPGRADING.md`.

### Security

- **A transposed key pair could publish the private key at the JWKS endpoint, and
  nothing caught it.** `DatabaseKeyManager` returned `array{0: string, 1: string}`
  destructured as `[$public, $private]` — both `string`, so swapping them was invisible
  to PHPStan, Pint and the type system, and the two build sites (sodium, OpenSSL) look
  nothing alike. Replaced with a `GeneratedKeyPair` value object, constructed with named
  arguments so reordering the constructor cannot re-transpose them.

  Six swap-detection tests were added across RS256/ES256/EdDSA, and they were needed:
  under a deliberate transposition the **pre-existing** EdDSA test still passed, so the
  Ed25519 secret key would have been published as an OKP JWK silently. The new guards
  assert the stored public column carries no private material, that the sealed half is
  the private key, that the two are provably the same pair, and that the JWKS contains
  no `d`/`p`/`q` and no PEM private block.

### Changed — breaking

- `Memberships::add()`, `Memberships::changeRole()` and `Invitations::invite()` take
  `MembershipRole`, not `string`. The enum's own docblock said an invalid role should be
  "a type error, not a silent fail-open" — the contract signature defeated that, so a
  typo was an uncaught `ValueError` (a 500) invisible to static analysis, on data feeding
  the last-owner guard and the console's admin checks. Parsing moved to the real edges:
  the CLI validates `--role` up front, and an unrecognised role in an import row is now a
  per-row `ImportError` naming the accepted values.
- `Connections` gains `samlConfig()` / `oidcConfig()` returning typed configuration.
  `config(): array` remains the unseal primitive, and `create()` deliberately keeps its
  array — a Draft connection is legitimately incomplete, and validating at create would
  make drafts unrepresentable.

### Fixed

- The membership audit payload recorded the raw string while the row persisted the enum,
  so a case-variant input diverged between the audit trail and the stored value.
- Eight `@var` annotations asserted a shape over decoded JSON that nothing verified;
  replaced with validating parses.
- `DatabaseDirectoryGroups` still carried a duplicated copy of the RFC 7644 PATCH op list
  as string literals; it now uses `ScimPatchOp` with an exhaustive `match`.

## [0.57.0] - 2026-07-26

Output of a whole-platform review loop: ten specialist passes, an independent
second-vendor review, adversarial verification of every high-severity finding, and a
re-review that caught eight regressions the fixes themselves introduced. Four findings
were refuted and dropped rather than "fixed"; several were re-priced down. See
`UPGRADING.md` — **this release refuses things earlier versions accepted.**

### Security

- **Invitations are environment-scoped.** `invitations` was the only credential-bearing
  table without an `environment_id`, and `byToken()` matched on the hash alone — so a
  token minted in one environment was redeemable on any host, minting an active user, a
  session, and tokens from the *victim* environment's issuer. Adding a plane gate would
  not have fixed it: a tenant subdomain is a valid subject-plane host.
- **`MembershipService::add()` refuses an organization from another environment.**
  `runAs()` sets only the tenant dimension, `BelongsToEnvironment` auto-fills on INSERT,
  and `memberships` has no foreign key — so a foreign org id was taken on trust.
- **Singletons no longer capture the `scoped` tenancy context.** A queue worker's
  `forgetScopedInstances()` unsets the binding without resetting an object a singleton
  already holds, so job B was written, keyed and delivered under job A's environment.
  Environment-owned models failed closed; the outbox, the audit chain and the JWKS cache
  did not. **Fifteen** classes were affected. `ScopedContextCaptureTest` now enforces the
  rule that a code comment had failed to.
- DPoP replay keys on `(jkt, jti)` rather than a global `jti`, closing a
  pre-registration DoS; proofs carry `environment_id`.
- `Permission`'s global scope fails closed instead of exposing the cross-environment
  catalog when no environment is in context.
- Entra directory pagination pins `@odata.nextLink` to the Graph host — the last
  outbound path not behind the SSRF gate.
- Webhook endpoints refuse plaintext `http://`.
- Tenant-routing cache keys use SHA-256 rather than a non-cryptographic hash.

### Added

- `cbox-id:prune` with per-table retention. **`audit_logs` is deliberately excluded**:
  the chain is hash-linked and checkpoint-anchored, so pruning below a checkpoint breaks
  verification and pruning to one removes the row the tamper check reads. Bounding audit
  growth needs export-then-rechain, not a sweep.
- `cbox-id:events:backlog` (`--json`, `--fail-over=N`), a `RelayBacklog` contract, and a
  configurable relay limit/cadence. Relay lag was previously silent.
- Webhook circuit breaker with self-healing, and outbox dead-lettering with an attempt
  counter — a listener that always throws no longer retries forever.
- SAML: POST-binding SLO, per-environment frozen EntityID, SP key material (so logout
  responses are signed and SP metadata carries a `KeyDescriptor`), multi-cert IdP
  rollover.
- `PackageConfigMerger` — published config now merges key-by-key, so a partial host
  config no longer discards package defaults. Lists replace rather than append.
- Cross-language golden fixtures for webhook signing and RFC 7638 thumbprints; real-vector
  tests for PKCE (RFC 7636 App. B), `at_hash`, and JWKS-only verification.

### Changed — behaviour visible to integrators

- Webhook delivery is **queued**. A host without a running queue worker will persist
  delivery rows and send nothing.
- `/authorize` returns `invalid_scope` for scopes outside the client's registered set,
  instead of silently narrowing. **Audit registered scope lists before deploying.**
- `scope` is echoed from `/oauth/token` whenever granted differs from requested
  (RFC 6749 §5.1).
- `max_age` and `acr_values` are honoured; an unsatisfiable request returns
  `unmet_authentication_requirements` rather than a downgraded token.
- SCIM: malformed `Operations` → 400; unknown-id DELETE → 404; `active` parsed strictly
  (case-insensitively); `GET /Groups` omits `members` unless requested;
  `userName`/email equality is case-insensitive on **all** drivers — Postgres tenants
  with case-variant duplicates will newly see `409` and need reconciliation first.
- SAML: `NameIDPolicy` enforced; signed `AuthnRequest`s require `Destination` and must
  address the receiving location; requests are single-use and time-bounded.
- `/up` returns JSON.

### Fixed

- `deleteRole()` left `group_role_mappings` behind, wedging directory reconciliation and,
  because the relay released the claim, blocking every listener registered after it —
  permanently.
- Orphaned webhook deliveries starved the retry sweep at the head of an ascending queue.
- The whole env-console role surface wrote through the query builder, leaving privileged
  changes with no audit entry and no domain event.
- `CachedEntitlements` no longer resurrects a pre-invalidation snapshot when its version
  counter is evicted.
- Redirect-binding SAML signatures verify over the transmitted octets, and survive the
  login hand-off.
- Missing indexes on token, session and delivery sweep columns.

## [0.56.0] - 2026-07-25

**Upgrading:** two contract changes. `PasswordPolicyGuard::assertAcceptable()` now
REQUIRES the subject id — the no-subject case is `assertAcceptableForNewSubject()`.
`Roles` gains `unassignAll()`; a custom implementation must supply it.

### Fixed

- **A removed member kept their RBAC grants.** `MembershipService::remove()` deleted the
  membership and left `role_assignments` behind. Assignments are read by (organization,
  user) with no membership join, so this was not litter: re-adding the person later
  silently restored privileges nobody re-granted, and anything reading assignments
  directly still saw them held. Removal now revokes them in the same transaction, one
  `role.unassigned` event per role. A deployment binding external RBAC owns its own
  grants, so its refusal is caught and the removal proceeds.

### Changed

- `PasswordPolicyGuard::assertAcceptable()` takes a non-optional `string $userId`, and
  the genuine no-subject case — signup, or an administrator seeding an account — is the
  separate `assertAcceptableForNewSubject()`. The optional argument used to buy a caller
  a weaker check for free: no reuse history, and the bare environment baseline instead of
  the organizations binding the subject. An exemption reachable by forgetting an argument
  looks identical to the case where it is correct.

## [0.55.1] - 2026-07-25

### Fixed

- `DatabaseAuthPolicies` memoized the environment baseline without keying the memo by
  environment. It is a singleton, and one process legitimately visits several
  environments — a queue worker draining jobs for different tenants, and every
  `PlatformRoot::run()` that steps into tenant 1 and back — so the first environment's
  policy was answered for all of them. Latent while the policy had few consumers;
  load-bearing since 0.53.0 put it on every credential path, where it would apply one
  tenant's password floor to another's people, in the direction tighten-only exists to
  forbid.

## [0.55.0] - 2026-07-25

**Upgrading:** `PlatformRoot::environment()` no longer accepts a configured default that
matches no environment row, or one that belongs to an account. A deployment relying on
either loses its platform root — which is the point; see below. `cbox-id:doctor` reports
which case you are in.

### Fixed

- **The platform root could be a customer's environment.** `PlatformRoot` fell back to
  `cbox-id.environments.default` without checking what that key pointed at. A deployment
  that never stamped an `is_default` row and aimed the config at a tenant environment
  wrote every account member's subject INSIDE that customer's tenant — where that
  customer's environment admins (including a Developer, a role explicitly denied the
  member roster) could set the password through the admin-password feature and sign in
  as an account member. The fallback now resolves to a real row and refuses one an
  account owns.
- **Three components resolved "the default environment" in two different orders.**
  `Api\Http\Middleware\ResolveEnvironment` preferred the config key while
  `PlatformRoot` and the console's `SetEnvironment`/`PlaneResolver` preferred the
  `is_default` row, so a deployment with both would answer "which tenant is this
  request" one way over the API and another on the web. All of them now take the row
  first: it is what the installer stamps and it survives horizontal scaling.

### Added

- A `cbox-id:doctor` check for the platform root. It fails on a configured default that
  belongs to an account, and warns when the root is resolved from config rather than a
  stamped row — the silent-at-runtime misconfigurations, which otherwise surface as an
  incident rather than a deploy-time message.

## [0.54.0] - 2026-07-25

`AuthPolicy`'s remaining three fields stop being decoration. `maxAgeDays`, `mfa` and
`lockoutThreshold` were stored, inherited and tightened correctly, and read by nothing.

**Upgrading:** two new tables. `password_ages` is seeded with every existing subject at
the upgrade time, so a `maxAgeDays` policy starts its clock for everyone at once rather
than never applying to anyone who predates it. Turning any of the three fields on now
changes behaviour where it previously changed nothing — review what your environments
have set before deploying.

### Added

- **`Identity\Contracts\PasswordExpiry`** — whether a subject's password has outlived
  `maxAgeDays`. Backed by `password_ages`, stamped by the credential primitive. A
  subject with no recorded age never expires: their credential predating this being
  tracked is not evidence of an old password.
- **`Identity\Contracts\MfaMandate`** — whether a subject still owes the tenant a second
  factor. Expressed as a question rather than a refusal, because turning away someone
  with no factor locks out precisely the people who need to enrol. A confirmed TOTP
  factor and a registered passkey both satisfy it.
- **`Identity\Contracts\LoginAttempts`** — per-SUBJECT failed-attempt counting and
  lockout at `lockoutThreshold`. Distinct from the IP-keyed rate limiting a sign-in form
  does: an attacker spreading guesses across a botnet never trips an IP limit, and a
  shared office NAT trips one with nobody being attacked.

### Changed

- `DatabaseAccountMembers` and `DatabaseSubjects` stamp the password age wherever a
  credential is written, for the same reason the policy is applied there.
- `docs/security/password-policy.md` documents all three, including the two durations
  that are deliberately NOT tenant-configurable: an indefinite lockout is a
  denial-of-service tool, and a counting window that never resets locks out people who
  occasionally mistype.

## [0.53.0] - 2026-07-25

The authentication policy is now applied where credentials are written, instead of on
whichever caller remembered to ask for it.

**Upgrading:** behavioural. `Subjects::create()` and `Subjects::setPassword()` throw
`PolicyViolation` for a password below the tenant's floor. Any code path that sets a
password with a value the policy refuses now fails where it previously succeeded —
including seeders, factories that go through `Subjects`, and plaintext bulk import.
Hash import (`storeCredential()`) is unaffected. A host application binding its own
`Subjects` resolver should apply the guard in the same two methods; the contract's
docblock says so.

### Added

- **`Identity\Rules\PasswordMeetsPolicy`** — a validation rule so a form surfaces a
  policy refusal on the field instead of as an unhandled exception. Use it *instead of*
  a hardcoded `min:` rule, not beside one: a fixed number cannot know what the tenant
  requires, and the smaller of the two silently defines the experience.
- `docs/security/password-policy.md` — where enforcement lives and why, how the
  organization is inferred when a caller does not name one, and what plaintext import
  means.

### Changed

- `DatabaseSubjects::create()` and `setPassword()` apply the policy and record the
  resulting hash in the reuse history themselves. Signup, invitation acceptance,
  self-service reset, administrative assignment and plaintext import all inherit it.
  `PasswordResetService` and `AdminPasswordService` lose their bolted-on copies.
- When no organization is named, `PasswordPolicyEnforcer` resolves the environment
  baseline tightened by **every** organization the subject belongs to. Resolving the
  bare baseline would let a member of a strict organization satisfy the looser
  environment floor through any path that did not carry org context.
- `DatabaseAccountMembers::activate()` and `resetPassword()` are transactional, so a
  policy refusal cannot leave the member row holding a rejected password or spend a
  single-use reset link on the way out.

### Fixed

- The password policy was enforced on administrative assignment and nowhere else. An
  environment demanding 24 characters got 24 from an admin and 12 — whatever the calling
  form hardcoded — from every self-service path.

### Known limitations

- `AuthPolicy`'s `mfa`, `lockoutThreshold` and `maxAgeDays` are stored, inherited and
  tightened correctly but **no sign-in path reads them**. They describe an intent the
  authentication flow does not yet act on.

## [0.52.0] - 2026-07-25

Unified account identity. An account member's **subject** becomes the credential of
record: members are ordinary subjects in the platform-root environment, holding a
membership in their account's organization. The account keeps its ownership and billing
role — what it loses is its own parallel way of authenticating people.

**Upgrading:** breaking. `account_members` gains `subject_id`, and credential operations
(`verifyPassword`, `resetPassword`, `activate`) now act on the member's subject. A
deployment with existing account members needs those subjects minted before sign-in
works; there is no backfill migration, because the platform had no external consumers at
the time of the cut.

### Added

- **`Platform\PlatformRoot`** — the single answer to "which environment is tenant 1".
  Subject and membership writes run inside its scope, since both rows are
  environment-owned and would otherwise be written against whatever scope happened to be
  current.
- `accounts.organization_id` and `account_members.subject_id`; `AccountProvisioner`
  creates the account's organization in the platform root alongside the account.
- `EnvironmentAdminGrant::$subjectId` — the signed handoff now carries the subject.

### Changed

- `DatabaseAccountMembers::create/invite` mint the member's subject in the platform root
  and add a membership in the account's organization. Credential verification and reset
  go to that subject.
- `remove()` revokes the organization membership and deactivates the subject unless
  another account still holds them.

### Security

- **An invited member's subject is minted deactivated.** An invitation must not be a way
  in before it is accepted.
- **An address that already has a subject is reused, never re-credentialed.** Otherwise
  inviting an email you do not control would reset that person's password.
- Account members inherit the tenant password policy, administrative password expiry and
  the SSO mandate, because they authenticate as subjects — previously none of those
  applied on the account plane.

## [0.51.0] - 2026-07-25

Second platform-review loop. Every finding was adversarially verified before it was
fixed: four of nine P1 reports were refuted and dropped (SAML SSO's missing org gate is
the intended environment-owned model; WebAuthn challenge replay is closed by the host
contract; device/CIBA approval derives the organization server-side; the JWT leeway
window is guarded by try/finally and unreachable without Octane).

**Upgrading:** `tenant_assignable` in an app manifest is now OPT-IN. A declared
permission without an explicit `"tenant_assignable": true` becomes internal on the next
manifest sync, where it was previously tenant-assignable by default. Review your
manifests before upgrading if tenants compose app permissions into their own roles.

### Added

- **Per-environment and per-organization authentication policy** (`AuthPolicies`,
  `AuthPolicy`). Minimum length, breach checking, maximum age, reuse history, MFA
  requirement and SSO enforcement. An environment sets the baseline; an organization may
  override it, but `AuthPolicy::tightenedWith()` takes the STRICTER value of every field,
  so an override can never weaken the operator's floor. `PasswordPolicyGuard` is the one
  enforcement point every credential path runs through. Two additive migrations
  (`auth_policies`, `password_history` — hashes only, pruned to the configured depth).
- **Administrative password assignment** (`AdminPasswords`). Sets a subject's credential
  directly — legitimate because this platform owns its user records — as either a
  temporary hand-off (must be replaced at next sign-in, with an optional deadline after
  which it stops authenticating) or a permanent password, with the revocation blast
  radius an explicit choice (`PasswordRevocationScope`). Every call is audited with the
  actor and their stated reason, and is held to the tenant's password policy.
  Authorization is deliberately the caller's responsibility. Additive migration
  (`password_change_requirements`).
- **`BreachedPasswordCheck`** contract, shipped with a deliberately-inert
  `NeverBreachedCheck` default: the lookup is a network call against a service the host
  operates, so the library refuses to imply protection it never wired up.
- **`cbox-id:doctor` warns when `authorization_endpoint` is unconfigured.** OpenID
  Connect Discovery §3 marks it REQUIRED, and a host that never set it shipped a
  discovery document conformant OIDC clients refuse to initialize against, with nothing
  surfacing that. A warning rather than a failure, because an OAuth-only
  (client_credentials) deployment legitimately has none.

### Security

- **One-time credentials are claimed with a conditional update, not a read-then-write.**
  Password-reset tokens, TOTP steps and MFA recovery codes could each be consumed twice
  by concurrent requests presenting the same value — spending one reset token on two
  password changes, or one recovery code on two sessions. Each now acts only if it won
  the row.
- **Last-owner protection locks the owner rows before counting.** Two owners each
  demoting or removing themselves at the same moment both read a count of two, both
  concluded they were not the last, and both committed — leaving an organization with no
  owner and no way to appoint one.
- **SCIM `User` PATCH rejects an unknown or missing `op`** with `400 invalidSyntax`
  (RFC 7644 §3.5.2). It previously fell through to a silent `replace`, so a typo'd
  operation mutated the resource and the calling IdP recorded a write that never
  happened. The Group path already enforced this; Users did not.
- **`tenant_assignable` is opt-in** (see Upgrading above): an omitted field no longer
  widens tenant self-serve access.

### Fixed

- **`at_hash` derives from the id_token's own signing algorithm** (OIDC Core §3.1.3.6)
  rather than a hardcoded SHA-256. Correct only because id_tokens happen to be RS256;
  an EdDSA id_token (Ed25519 signs over SHA-512) would have carried a digest a strict
  relying party rejects.
- **Environment-wide audit browse no longer filesorts.** Adds the
  `(environment_id, sequence)` index; the organization-filtered export cursor already
  had its own composite and is unaffected.
- Manual permissions authored in a console are stamped with their authoring environment.
  Additive backfill migration derives the environment from each row's bound roles where
  unambiguous; it is intentionally irreversible (`down()` is a no-op, because a set value
  cannot be told apart from a pre-existing one).

### Changed

- **The Usage kernel no longer imports a domain module.** `UsageReconciler` depends on a
  new `SeatCensus` contract (implemented in the Organization module) instead of
  `Organization\Contracts\Memberships`. `src/Kernel` now imports no domain module at all.
- Device/CIBA poll status and service-account status are typed enums (`GrantPollStatus`,
  `ServiceAccountStatus`) — the token-mint guard was a string comparison. Platform
  repositories write those enums instead of raw strings past their casts.

### Tests

- **SAML XML Signature Wrapping**, both classic placements: the genuine signature stays
  valid and a forged assertion is smuggled beside it. Refused by the single-assertion
  rule. Verified non-vacuous — the test fails if that guard is removed.
- Recovery-code single-use, the org-can-only-tighten policy invariant, and an
  administrator being held to the tenant policy.
- Two test files declared `SP_ACS` at global scope with different values; load order
  silently decided which URL was tested.

## [0.50.0] - 2026-07-24

Bring-your-own RBAC. The platform can now run its AuthN/SSO/OAuth/OIDC/SCIM stack on
top of an external authorization backend (e.g. an existing `spatie/laravel-permission`
install) instead of its own RBAC — see the `cboxdk/laravel-id-spatie` adapter.

### Added

- **External access-control driver** (`access_control.driver`, `builtin` default or
  `external`). Under `external` the built-in RBAC tables and their migrations are not
  loaded, and the `AccessChecker`/`Roles`/`GroupRoleMappings` contracts fall back to a
  deny-by-default: `NullAccessChecker` refuses every check and stamps empty token
  claims, while `UnboundRoles`/`UnboundGroupRoleMappings` throw `ExternalRbacNotBound`
  so a write or SCIM group→role sync fails loud rather than writing to absent tables.
  A host binding wins over the fallback. See `docs/extension-points/custom-rbac.md`.

### Changed

- The built-in RBAC migrations moved into a `database/migrations/access-control/`
  subdirectory so the auto-loader can gate them on the driver (the shared loader's glob
  is non-recursive). Migration publishing flattens every migration into the host's
  `database/migrations`, so published output is unchanged. No behavior change under the
  default `builtin` driver.

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
  [Environments & the isolation model](docs/core-concepts/environments.md).
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
