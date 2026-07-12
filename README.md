# Cbox ID

**`cboxdk/laravel-id`** — a self-hostable, Laravel-native identity platform. Central login,
enterprise SSO, directory sync, RBAC, billing-driven entitlements and a tamper-evident audit
trail — all interface-driven, deny-by-default, and verified (tests + PHPStan level max +
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
use Cbox\Id\Identity\Contracts\UserDirectory;

$org  = app(Organizations::class)->create(new NewOrganization('Northwind', 'northwind'));
$user = app(UserDirectory::class)->create('ida@northwind.test', 'Ida', password: 's3cret');
```

## Modules

| Layer | Modules |
|---|---|
| Kernels | `Tenancy` · `Crypto` · `Audit` · `Events` · `Authorization` |
| Domain | `Organization` · `Identity` · `AccessControl` · `Directory` (SCIM) · `Federation` (SSO) · `Webhooks` · `AuditQuery` |

## Documentation

Full docs live in [`docs/`](docs/index.md):

- [Installation](docs/getting-started/installation.md) · [Quickstart](docs/getting-started/quickstart.md)
- [Architecture & patterns](docs/architecture.md)
- [Cookbook](docs/cookbook.md)
- [Extending & customizing](docs/extending.md)
- [Testing](docs/testing.md)
- [Security](docs/security.md) · [`SECURITY.md`](SECURITY.md)
- [Standards & conformance](docs/standards.md) — RFCs implemented (OAuth/OIDC/SCIM/SAML/MCP)

## License

MIT. Private during internal dogfooding; public release when ready.
