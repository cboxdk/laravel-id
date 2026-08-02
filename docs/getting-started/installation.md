---
title: Installation
description: Install the package, configure the crypto key, run migrations
weight: 1
---

# Installation

> **Environments — read this first.** Every domain model (`Organization`, `User`,
> `SigningKey`, sessions, connections…) is **environment-owned** with a
> deny-by-default scope: with no environment in context, reads return nothing and
> writes hit a NOT NULL `environment_id`. So an environment must exist **and be in
> context** before the domain models (and the [Quickstart](../quickstart.md)
> snippets) do anything. A request resolves its environment from the host
> (`ResolveEnvironment` middleware, backed by an `EnvironmentResolver`); for a
> single-tenant / on-prem deployment set `cbox-id.environments.default` to your one
> environment key. The first environment is provisioned outside request scope — the
> deployable app (cbox-id) creates it from its operator console; in tests you pin one
> with `actingAsEnvironment('env_test')`. See
> [Environments & the isolation model](../core-concepts/environments.md).

## Requirements

- PHP `^8.4` (developed on 8.5)
- Laravel 12 or 13
- `ext-openssl`, `ext-sodium`
- A database CI actually tests: **PostgreSQL 14+**, **MySQL 8.0.13+**, **MariaDB
  10.2+** or **SQLite**. Every CI run migrates against all four and runs the full test
  suite on PostgreSQL, MySQL, MariaDB and SQLite — all four are green, and the per-engine
  numbers are in [Requirements](../requirements.md). This page claimed MariaDB was still
  failing long after it stopped, while pointing at the page that says otherwise.
  PostgreSQL remains the recommended production default — and is now covered by the
  suite, which it was not before v0.62.0. **SQL Server is not tested and not
  supported**: nobody has ever run it, so it is not promised.

## Install

```bash
composer require cboxdk/laravel-id
```

The package auto-registers `Cbox\Id\IdServiceProvider`, which wires every kernel and domain
module and loads the migrations.

## Configure the crypto master key

Envelope encryption (connection configs, MFA secrets, private signing keys, webhook secrets)
needs a 32-byte master key. Generate one and set it in your environment:

```bash
php -r "echo base64_encode(random_bytes(32)).PHP_EOL;"
```

Set the value as **raw base64** — the form the generator above prints, and the form
the app's `docker-compose.yml` uses:

```dotenv
CBOX_ID_CRYPTO_KEY=...your base64 key...
```

An optional `base64:` prefix is also accepted (so operators coming from Laravel's
`APP_KEY` muscle-memory aren't surprised) — `CBOX_ID_CRYPTO_KEY=base64:...your base64 key...`
decodes to the same 32-byte key. Either form works; raw is the recommended, canonical one.

> Back this key up **separately from the database**. Lose it and every sealed secret —
> including private signing keys — becomes unrecoverable.

Prefer a guided setup? `php artisan cbox-id:install` generates the key, writes it to
`.env`, runs the migrations and mints the first signing key in one step; `php artisan
cbox-id:doctor` then verifies the install.

Publish the config if you want to review it:

```bash
php artisan vendor:publish --tag=cbox-id-config
```

You do not have to keep the whole file. Package defaults are merged UNDER your published
config key by key, at every depth, so a `config/cbox-id.php` containing only the settings
you actually override is enough — everything you leave out keeps working, and the env vars
behind it keep working too.

Two rules are worth knowing before you trim it:

- **Your value always wins**, including `null`, `false` and `0`. Omitting a key is not the
  same as setting it — an omitted key takes the package default.
- **A list replaces, it never appends.** Where a setting is a sequential array
  (`api.middleware`, `oauth.dynamic_registration.allowed_scopes`) yours is used whole, so
  you can shrink one, or empty it with `[]`, without the package's entries coming back.

`php artisan config:show cbox-id` prints the merged result — what your deployment actually
resolves, not what is in the file.

## Migrate

```bash
php artisan migrate
```

That creates the environments, organizations, identities, sessions, connections,
directories, roles, audit, events, entitlements, signing-keys, OAuth and webhook tables.
It does **not** create a `users` table — the platform integrates with the host's user
store rather than owning it.

### The users table — greenfield vs. an existing app

The default migration set deliberately omits a `users` table. Which path you take
depends on whether you already have one:

- **Greenfield (no users table yet).** Publish the optional canonical users migration
  via its own tag, then migrate:

  ```bash
  php artisan vendor:publish --tag=cbox-id-users-migration
  php artisan migrate
  ```

- **Existing app (you already have a users table).** Don't publish it. Bind your own
  implementation of the `Subjects` contract (config `cbox-id.subject.resolver`) and map
  the platform's opaque subject ids onto your model(s) — the platform never assumes
  ownership of your users table. See
  [Integrating an existing app](../cookbook/integrating-existing-apps.md).

## Verify

```bash
php artisan cbox-id:doctor
```

`doctor` establishes an environment for itself, which is why it is the check to run.

Reaching for `tinker` here does not work, and the reason is worth knowing: a signing key
is environment-owned, and nothing on the command line resolves an environment — every
setter in the application is HTTP middleware. So `activeSigningKey()` in a REPL either
falls through to generating a key it cannot stamp, or fails on the NOT NULL constraint.
If you want it from a REPL, set `cbox-id.environments.default` first, or wrap the call in
`EnvironmentContext::runAs()`.

A clean `doctor` run means the platform booted, generated its first signing key, sealed
the private half, and can reach everything it needs. Next: the
[Quickstart](../quickstart.md).
