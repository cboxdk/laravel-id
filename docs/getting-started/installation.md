---
title: Installation
description: Install the package, configure the crypto key, run migrations
weight: 1
---

# Installation

## Requirements

- PHP `^8.4` (developed on 8.5)
- Laravel 12
- PostgreSQL 16 (SQLite works for tests)
- `ext-openssl`, `ext-sodium`

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

```dotenv
CBOX_ID_CRYPTO_KEY=base64:...your key...
```

> Back this key up **separately from the database**. Lose it and every sealed secret —
> including private signing keys — becomes unrecoverable.

Publish the config if you want to review it:

```bash
php artisan vendor:publish --tag=cbox-id-config
```

## Migrate

```bash
php artisan migrate
```

That creates the organizations, users, sessions, connections, directories, roles, audit,
events, entitlements, signing-keys and webhook tables.

## Verify

```bash
php artisan tinker
>>> app(\Cbox\Id\Kernel\Crypto\Contracts\KeyManager::class)->activeSigningKey()->kid;
```

A `kid` string means the platform booted, generated its first signing key, and sealed the
private half. Next: the [Quickstart](quickstart.md).
