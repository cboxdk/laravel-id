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
- Any database Laravel supports — MySQL/MariaDB, PostgreSQL, SQLite, SQL Server.
  Nothing is pinned (the test suite runs on SQLite in-memory); PostgreSQL is a fine
  production default but only a recommendation, not a requirement. See
  [Requirements](../requirements.md).

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
php artisan tinker
>>> app(\Cbox\Id\Kernel\Crypto\Contracts\KeyManager::class)->activeSigningKey()->kid;
```

A `kid` string means the platform booted, generated its first signing key, and sealed the
private half. Next: the [Quickstart](../quickstart.md).
