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
Eloquent, so any database Laravel supports (MySQL/MariaDB, PostgreSQL, SQLite,
SQL Server) should work; the automated test suite exercises **SQLite in-memory**.
Entitlement and session hot-paths benefit from a cache store (Redis recommended
in production) but do not require one.
