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

| Engine | Migrations (up **and** down) | Full test suite |
|---|---|---|
| SQLite (in-memory) | ✅ every CI run | ✅ every CI run — 1357 passed, 1 skipped |
| MySQL 8.0.13+ | ✅ every CI run (`engines` job, `mysql:8`) | ✅ every CI run — 1358 passed |
| MariaDB 10.2+ | ✅ every CI run (`engines` job, `mariadb:11`) | ⚠️ **not yet** — 6 of 1358 fail, see below |
| PostgreSQL 14+ | ✅ every CI run (`engines` job, `postgres:16`) | ⚠️ **not yet** — 338 of 1358 fail, see below |
| SQL Server | ❌ never run | ❌ never run |
| Others (Oracle, …) | Not supported. | |

The MySQL and MariaDB floors are the releases that introduced *expression* column
defaults (`DEFAULT (json_object())`); nothing older can express a default on a `json`
column at all, so the schema simply will not build there.

### The two engines whose suite is not green yet

Both are pre-existing product defects that this CI job **found**; neither is a
migration problem, and the schema itself is correct on all four engines.

**PostgreSQL — `char(26)` blank padding.** `$table->ulid()` compiles to `char(26)`.
PostgreSQL blank-pads `CHAR` on read; MySQL and SQLite strip the trailing spaces. Any
environment key shorter than 26 characters therefore comes back padded and the tenancy
guard rejects its own row — `row belongs to [env_test⎵⎵⎵…], acting as [env_test]`.
338 of 1358 tests fail that way on `postgres:16`. It does not bite a real deployment,
because a real environment id *is* a 26-character ULID — which is exactly why it went
unnoticed. Tracked as its own defect.

**MariaDB — first-append deadlock on an empty audit chain.** Eight processes appending
to a chain that has no rows yet have no anchor row to serialise on, so each takes a gap
lock on the `(environment_id, scope, sequence)` unique key. MariaDB resolves that
pile-up as SQLSTATE 40001 (error 1213, deadlock) rather than the duplicate-key error
`DatabaseAuditLog::record()` is written to absorb, and `attempts: 3` is not enough for
eight contenders on one gap: 6 of 800 appends failed. They failed **loudly** — the
caller gets an exception, nothing is silently dropped — and once the chain has its
first row the anchor works normally. The same test lands 800/800 on MySQL 8.4. If you
run MariaDB and have many concurrent writers hitting a brand-new environment, expect
those first appends to need application-level retry.

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
