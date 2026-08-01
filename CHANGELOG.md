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

- **`AuthPolicies::overridesFor()`** reads every organization's override in one query.
  Memoising the single-organization form removed the DUPLICATE reads but not the shape:
  a subject in nine organizations still cost nine queries on every authenticated request.
  Absences are memoised too, or a subject with no overrides re-reads all of them next
  time. `DatabasePasswordExpiry` and `DatabaseMfaMandate` both use it.

- **`DatabaseAuthPolicies::overrideFor()` was the one policy read not memoised**, and the
  one called in a loop: `PasswordExpiry` and `MfaMandate` both walk the signed-in
  subject's memberships asking for each organization's override, from that same
  middleware. Measured on a console page before the fix: 17 queries at one organization,
  22 at four, 32 at nine — exactly two per organization, on every request. Now memoised
  per request, keyed by environment AND organization for the same reason
  `forEnvironment()` is, and cleared on every write.

### Changed

- **`AuthPolicies` gained `overridesFor()`.** Breaking for a host that implements the
  contract itself — see [`UPGRADING.md`](UPGRADING.md). Hosts using the shipped binding
  need to do nothing.

### Testing

- The batch read is proven at twelve organizations — half with an override, half without
  — costing one query cold and none warm.
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
