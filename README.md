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

## What's supported

Grades are against this package's own `src/` — never the deployable app or an add-on.
**Full** = ships and is tested · **Partial** = works, with the named limit · **Contract
only** = you bind the implementation · **Host** = your app writes the interactive half ·
**No** = not implemented. Every row is expanded, with its caveats, in
[Standards & conformance](docs/security/standards.md) and
[Feature support](docs/capabilities/feature-support.md).

| Area | Support |
|---|---|
| **OAuth 2.0** | **Full** authorization-code + PKCE `S256` (RFC 7636), client-credentials, refresh with rotation + reuse detection, RFC 8414 / 9728 metadata · **Partial** introspection (RFC 7662), revocation (RFC 7009), device grant (RFC 8628), PAR (RFC 9126), DPoP (RFC 9449), token exchange (RFC 8693), resource indicators (RFC 8707), DCR (RFC 7591/7592) · **No** ROPC, implicit, mTLS (RFC 8705), JAR (RFC 9101), JARM, step-up challenge (RFC 9470) |
| **OpenID Connect** | **Full** discovery, JWKS, UserInfo, RP-Initiated Logout · **Partial** id_token (code flow + `query` mode only), CIBA (poll only) · **Host** `/authorize`, consent, `prompt`/`max_age`/`acr_values` gating, RFC 9207 `iss` · **No** front-channel or back-channel logout, pairwise `sub` |
| **SAML 2.0** (IdP role) | **Full** signed assertions and responses, RSA-SHA256, HTTP-Redirect + HTTP-POST, signed-`AuthnRequest` verification, XSW-hardened, SP-initiated SLO · **No** HTTP-Artifact, outbound assertion encryption, unsolicited SSO, global logout fan-out |
| **SAML 2.0 / OIDC** (relying party) | **Full** ACS with replay protection, JIT provisioning, JWKS rotation, `state`/`nonce` · **Partial** SLO (receive-only), inbound assertion decryption · **No** signed outbound `AuthnRequest`, PKCE on the outbound OIDC leg |
| **SCIM 2.0** | **Full** Users + Groups CRUD, Enterprise User extension (RFC 7643), errors and discovery (RFC 7644) · **Partial** PATCH, filtering, attribute selection · **No** sorting, ETags, `/Bulk`, `/.search`, `/Me` |
| **Provisioning out** | **Partial** generic SCIM 2.0 client with outbox, retries, circuit breaker, SSRF guard — **users only, no group push**, no vendor connectors |
| **Directory in** | **Full** SCIM push, Google Workspace and Microsoft Entra pull; deprovision revokes sessions immediately |
| **MFA & credentials** | **Full** recovery codes, magic links, password reset, password policy (length/reuse/expiry/lockout) · **Partial** TOTP (RFC 6238, SHA-1/6/30 fixed), WebAuthn/passkeys (ES256+RS256, `none` + self-attested `packed`), email OTP · **Contract only** breach screening, SMS OTP · **No** HOTP (RFC 4226), complexity classes |
| **Authorization** | **Full** org-scoped RBAC with hierarchy roll-down, entitlements, `POST /oauth/decisions` · **Partial** ReBAC engine (uncached), the PDP (ReBAC-only) · **No** wildcard permissions, role-inherits-role, XACML |
| **Audit** | **Full** SHA-256 hash chain, query + pull stream, retention · **Partial** signed checkpoints (nothing schedules them), SIEM streaming (HTTP transport only: Splunk HEC / ECS / GELF / CEF / JSON) · **No** tamper-*proof* storage, OCSF |
| **Governance** | **Full** access-certification campaigns · **Partial** Segregation of Duties — both cover roles and memberships only |
| **Crypto** | **Full** XChaCha20-Poly1305 AEAD at rest, signing-key rotation with overlap, closed `RS256`/`ES256`/`EdDSA` allow-list (RFC 8725, RFC 8037), JWKS (RFC 7517), `at+jwt` (RFC 9068) · **Contract only** HSM/KMS · **No** JWE (RFC 7516), master-key rotation |
| **Delivery** | **Full** transactional outbox, webhooks (HMAC-SHA256, retries, circuit breaker), six inline hook points · **Partial** at-least-once only; the webhook signature is proprietary, not Standard Webhooks |

> **This package does not serve `/authorize`.** It ships the back-channel — token,
> introspection, revocation, registration, PAR, device, CIBA, discovery, JWKS — and the
> crypto and validation behind them. Login, consent, and everything decided *at* the
> authorization request are your app's, and are marked **Host** above. The deployable
> **cbox-id app** implements that half if you would rather not.

## Modules

| Layer | Modules |
|---|---|
| Kernels | `Tenancy` · `Crypto` · `Audit` · `Events` · `Authorization` · `Usage` |
| Domain | `Organization` · `Identity` · `Otp` · `AccessControl` · `Directory` (inbound SCIM + pull connectors) · `Provisioning` (outbound SCIM) · `Federation` (SSO relying party) · `SamlIdp` (SAML 2.0 IdP) · `OAuthServer` (OAuth 2.0 / OIDC) · `Governance` (access reviews, SoD) · `TokenVault` · `ExternalActions` (inline hooks) · `Webhooks` · `AuditQuery` · `AuditStreaming` |
| HTTP & ops | `Api` (OAuth/OIDC/SCIM/SAML endpoints) · `Platform` (operators + the self-serve account/project plane) · `Maintenance` (retention) · `Console` (15 `cbox-id:*` commands) |

## Documentation

Full docs live in [`docs/`](docs/index.md):

- [**Capabilities**](docs/capabilities/_index.md) — the full support matrices and what each grade means
- [Requirements](docs/requirements.md) · [Installation](docs/getting-started/installation.md) · [Quickstart](docs/quickstart.md)
- [**Upgrading**](UPGRADING.md) — breaking changes and what to do about them, read this before crossing a version
- [Operations](docs/operations/_index.md) — the queue worker and scheduler the platform needs, and retention
- [Architecture & patterns](docs/core-concepts/architecture.md)
- [Cookbook](docs/cookbook/_index.md)
- [Extending & customizing](docs/extension-points/_index.md)
- [Testing](docs/getting-started/testing.md)
- [Security](docs/security/_index.md) · [`SECURITY.md`](SECURITY.md)
- [Standards & conformance](docs/security/standards.md) — the RFC-by-RFC matrix (OAuth/OIDC/SCIM/SAML/WebAuthn/MCP) · [Feature support](docs/capabilities/feature-support.md)
- [Compliance mapping](docs/security/compliance.md) — SOC 2 / ISO 27001 / NIS2 / GDPR / HIPAA / PCI-DSS · [Threat model](docs/security/threat-model.md)

## License

MIT. Published on Packagist as a pre-1.0 (`0.x`) release — installable via `composer
require cboxdk/laravel-id`; the API may still shift before 1.0.
