---
title: Requirements
description: Runtime and framework versions cboxdk/laravel-id needs
weight: 3
---

# Requirements

These are taken directly from the package's `composer.json` — the resolver
enforces them, so this page only explains them.

## Runtime

| Requirement | Version | Why |
|---|---|---|
| PHP | `^8.4` | Uses PHP 8.4 language features throughout. |
| ext-openssl | * | RSA/EC key generation and signing (JWT `RS256`/`ES256`, SAML). |
| ext-sodium | * | Ed25519 signing and XChaCha20-Poly1305 AEAD for secrets at rest. |

## Framework

| Requirement | Version |
|---|---|
| Laravel (`illuminate/*`) | `^12.0 \|\| ^13.0` |

The package is framework-native: it registers `Cbox\Id\IdServiceProvider` via
package auto-discovery and publishes migrations and config through it.

## Composer dependencies

Pulled in automatically by `composer require cboxdk/laravel-id`:

| Package | Version | Used for |
|---|---|---|
| `cboxdk/laravel-ssrf` | `^1.0` | SSRF guard + DNS pinning for outbound webhooks. |
| `firebase/php-jwt` | `^7.0` | JWT signing/verification (access tokens, DPoP, id_token). |
| `onelogin/php-saml` | `^4.0` | SAML 2.0 response validation (signatures, XSW/XXE defense). |
| `spomky-labs/cbor-php` | `^3.0` | CBOR decoding for WebAuthn/passkey attestation. |
| `cboxdk/laravel-siem` | `^0.1` | Delivery engine for SIEM audit streaming. |
| `cboxdk/siem` | `^0.1` | SIEM payload formats (Splunk HEC, ECS, GELF, CEF). |
| `robrichards/xmlseclibs` | `^3.1.5` | XML-DSig signing for SAML IdP assertions and metadata. |

## Storage

A relational database. Migrations use Laravel's standard schema builder and
Eloquent — but "standard schema builder" is not the same as "runs anywhere". For
sixty releases this page claimed four engines while the migrations could not create
a single table on MySQL (a `json` column cannot take a literal `DEFAULT`, error
1101). So this table now says only what CI proves:

| Engine | Migrations up | Migrations down | Full test suite |
|---|---|---|---|
| SQLite (in-memory) | ✅ every CI run | ✅ every CI run | ✅ every CI run — 1358 passed, 1 skipped |
| MySQL 8.0.13+ | ⚠️ not currently proven | ⚠️ not currently proven | ⚠️ not currently proven |
| PostgreSQL 14+ | ⚠️ not currently proven | ⚠️ not currently proven | ⚠️ not currently proven |
| MariaDB 10.2+ | ⚠️ not currently proven | ⚠️ not currently proven | ⚠️ not currently proven |
| SQL Server | ❌ never run | ❌ never run | ❌ never run |
| Others (Oracle, …) | Not supported. | | |

> **The `engines` job is not currently proving anything, and this table said it was.**
> The matrix exists and its service containers start and report healthy, but the job
> has never reached one: it addresses the database at `127.0.0.1` on the published
> port, which only works when the job runs on the runner host. This runner mounts the
> host's Docker socket, so the port is published on the host while the job runs in a
> container that is on neither that loopback nor the service network. Every run has
> failed with `SQLSTATE[HY000] [2002] Connection refused`.
>
> That is the same failure this page's own preamble describes — a claim of four
> engines that CI was not actually checking — arrived at a second time by a different
> route. The rows above will say ✅ again when the job connects, and not before.
>
> What *is* known: the schema rules below were derived from real failures on real
> servers, and the sibling application `cboxdk/cbox-id` has had its suite run against
> MySQL 8.4 and PostgreSQL 17 by hand. Neither is a substitute for this package's own
> matrix passing.

The MySQL and MariaDB floors are the releases that introduced *expression* column
defaults (`DEFAULT (json_object())`); nothing older can express a default on a `json`
column at all, so the schema simply will not build there.

### `down()` is now covered, and was not before

That column is new, and it was added the honest way. For sixty releases the `engines`
job carried a step captioned "migrations up and down" that rolled back **nothing**:
Testbench's rollback is scoped by `--path` to the one publishable migration the
TestCase loads directly, so everything the service provider registers went up and never
came back down. Measured on `postgres:16` against an empty database, 83 tables and 90
rows in `migrations` survived the step. Nothing noticed, because `migrate:rollback`
exits 0 whether it reversed the whole schema or a single file and nothing looked at the
database afterwards.

`tests/Migrations/MigrationRollbackTest.php` is the replacement. It migrates **every**
registered path into a throwaway database, runs `migrate:reset` across all of them, and
requires **zero** tables and **zero** `migrations` rows before migrating back up again.
The assertion is the point; the rollback on its own proves nothing. It runs on all four
engines, including MariaDB.

It found five migrations whose `down()` was broken on first run. One left a stray
`password_reset_tokens` table behind after a full reset — the same name whose collision
with Laravel's skeleton migration broke every greenfield install in v0.62.0, so a
rolled-back database could not be migrated forward again.

One migration is deliberately irreversible and documented as such:
`access-control/2026_07_24_000300_backfill_manual_permission_environments` is a data
backfill that cannot distinguish an `environment_id` it set from one already present,
so reverting would risk nulling legitimately-scoped rows.

### Both engines that were not green are green now

Two defects each took a whole engine out of CI. Both were **found** by this job, both
are fixed, and both are kept here because the shape of each is worth knowing before you
add a migration or a concurrent write path.

**MariaDB — first-append deadlock on an empty audit chain.** Eight processes appending
to a chain with no rows yet had no anchor to serialise on, so the `FOR UPDATE` looking
for it matched nothing — which InnoDB answers with a **gap lock** on the
`(environment_id, scope, sequence)` unique key. MariaDB resolved the pile-up as
SQLSTATE 40001 (error 1213, deadlock) rather than the duplicate-key error
`DatabaseAuditLog::record()` is written to absorb, and three attempts is not enough for
eight contenders on one gap: **6 of 800 appends failed**, loudly rather than silently.

Fixed by finding the anchor with a plain read and locking it by **primary key** — an
exact primary-key match takes a record lock and can never take a gap lock — with the
search deliberately **outside** the transaction, because under `REPEATABLE READ` a
consistent read inside it fixes the snapshot the head read is then answered from. That
second half is not obvious from the documentation; an earlier attempt that kept the
lookup inside the transaction made it strictly worse. Now **1386/1386 on `mariadb:11`**,
and 800/800 on the forking test.

**PostgreSQL is green as of v0.62.0**, and was not before: `$table->ulid()` compiled to
`char(26)`, which PostgreSQL blank-pads, so every id shorter than 26 characters came
back to PHP padded and failed strict comparison — 338 of 1358 tests. Every identifier
column is `varchar` now. See [Upgrading](../UPGRADING.md) for the migration, and the
note below before you add a column.

**SQL Server is not supported.** It has never been run, by CI or by hand. The schema
uses nothing knowingly incompatible with it, but "nothing knowingly incompatible" is
exactly what this page used to say about MySQL.

Entitlement and session hot-paths benefit from a cache store (Redis recommended
in production) but do not require one.

### Portability constraints the schema is written against

Worth knowing before you add a migration to this package:

- **A `json` column cannot carry a literal default on MySQL.** Only the
  parenthesised expression form, `DEFAULT (json_object())`, is accepted. (MariaDB's
  `json` is really `longtext` + a `json_valid()` CHECK and does take the literal —
  but it takes the expression too, so one spelling serves both.) Use
  `Cbox\Id\Kernel\Database\JsonDefault::emptyObject()` / `::emptyArray()`, which
  picks per driver and leaves the PostgreSQL and SQLite DDL untouched.
- **InnoDB caps an index key at 3072 bytes**, and utf8mb4 charges 4 bytes per
  character — so a composite index over four `string()` columns is already over the
  limit at the framework's `varchar(255)` default. Give columns that sit in a
  composite index an explicit length.
- **Index and constraint names must fit in 63 characters** — Postgres's limit, one
  tighter than MySQL's 64. Postgres truncates silently rather than failing, so an
  over-long generated name means the same index is called different things on
  different engines. Name long composite indexes explicitly.
- **Never declare a `CHAR` column** — not `char()`, and not the `ulid()` / `uuid()` /
  `foreignUlid()` / `ulidMorphs()` helpers that compile to one. PostgreSQL implements
  `CHAR` as `bpchar`, which blank-pads every value out to the declared width and hands
  the padding to PHP through PDO. `$row->environment_id === 'env_test'` is then false
  for a row whose `environment_id` *is* `env_test` — while Postgres' own `=` and
  `length()` strip the blanks, so the padding is invisible from a SQL client. Use
  `string($column, 26)`: `varchar` does not pad on any supported engine.
  `tests/Feature/SchemaPortabilityTest.php` fails the build if a `CHAR` helper
  reappears, and it runs on sqlite so it catches it on the first local run rather than
  in the server-engine job.
