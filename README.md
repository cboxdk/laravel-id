# Cbox ID

**`cboxdk/laravel-id`** is a Laravel-native auth and identity framework. Central login,
enterprise SSO, directory sync, RBAC, billing-driven entitlements and a tamper-evident audit
trail: all interface-driven, deny-by-default, and verified (tests + PHPStan level max +
`composer audit`) before it ships.

UI-free and domain-free: every capability sits behind a contract you bind, mock, extend or
replace.

## Install

```bash
composer require cboxdk/laravel-id
php -r "echo base64_encode(random_bytes(32)).PHP_EOL;"   # set as CBOX_ID_CRYPTO_KEY
php artisan migrate
```

## A taste

```php
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Cbox\Id\Identity\Contracts\Subjects;

$org  = app(Organizations::class)->create(new NewOrganization('Northwind', 'northwind'));
$user = app(Subjects::class)->create('ida@northwind.test', 'Ida', password: 's3cret');
```

> **Environments first.** `Organization`, `User` and the other domain models are
> environment-owned and deny-by-default — the calls above need an environment in context
> (a request resolves one from its host, or set `cbox-id.environments.default`; the
> deployable app creates the first one from its operator console). See
> [Environments & the isolation model](docs/core-concepts/environments.md).

## Modules

| Layer | Modules |
|---|---|
| Kernels | `Tenancy` · `Crypto` · `Audit` · `Events` · `Authorization` |
| Domain | `Organization` · `Identity` · `AccessControl` · `Directory` (SCIM) · `Federation` (SSO) · `OAuthServer` (OAuth 2.0 / OIDC provider) · `Webhooks` · `AuditQuery` |
| HTTP & ops | `Api` (OAuth/OIDC/SCIM endpoints) · `Platform` (operators + the self-serve account/project/billing plane) · `Console` (`cbox-id:install` / `cbox-id:doctor`) |

## Documentation

Full docs live in [`docs/`](docs/index.md):

- [Requirements](docs/requirements.md) · [Installation](docs/getting-started/installation.md) · [Quickstart](docs/quickstart.md)
- [Architecture & patterns](docs/core-concepts/architecture.md)
- [Cookbook](docs/cookbook/_index.md)
- [Extending & customizing](docs/extension-points/_index.md)
- [Testing](docs/getting-started/testing.md)
- [Security](docs/security/_index.md) · [`SECURITY.md`](SECURITY.md)
- [Standards & conformance](docs/security/standards.md) — RFCs implemented (OAuth/OIDC/SCIM/SAML/MCP)
- [Compliance mapping](docs/security/compliance.md) — SOC 2 / ISO 27001 / NIS2 / GDPR / HIPAA / PCI-DSS · [Threat model](docs/security/threat-model.md)

## License

MIT. Published on Packagist as a pre-1.0 (`0.x`) release — installable via `composer
require cboxdk/laravel-id`; the API may still shift before 1.0.
