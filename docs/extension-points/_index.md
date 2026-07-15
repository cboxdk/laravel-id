---
title: Extending & Customizing
description: Swap any contract, decorate behaviour, and implement a SAML/OIDC validator
weight: 5
---

# Extending & Customizing

Because every capability is a contract bound in the container, extension is just a binding.

Topic guides:

- **[Hash verifiers](hash-verifiers.md)** — accept a foreign password-hash format
  during a migration.
- **[Custom SCIM attribute mapping](custom-scim-attribute-mapping.md)** — control
  how platform user attributes map onto the SCIM `User` schema pushed to a
  downstream app.
- **[Custom OTP channel](custom-otp-channel.md)** — swap, add, or decorate how
  one-time passcodes are delivered (e.g. wire an SMS provider behind the contract).
- **[Custom secret vault](custom-secret-vault.md)** — back the AI token vault with
  an HSM or external secrets manager while keeping the deny-by-default grant model.

## Swap an implementation

Rebind any contract in a service provider — yours wins over the package default:

```php
use Cbox\Id\Identity\Contracts\Subjects;

$this->app->singleton(Subjects::class, MySubjects::class);
```

Your class implements the same interface. Callers are untouched because they depend on the
contract, not the class.

## Decorate behaviour

Wrap the package implementation to add cross-cutting behaviour (metrics, extra validation,
notifications) without forking it:

```php
$this->app->extend(Subjects::class, function (Subjects $inner, $app) {
    return new NotifyingSubjects($inner, $app->make(Notifier::class));
});
```

## Override a model's tenant column

Tenant-owned models use the `BelongsToTenant` trait and default to an `organization_id` column.
Override `tenantColumn()` if your table differs. Every tenant-owned model must also implement
`TenantOwned` — that's what engages the global scope.

```php
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToTenant;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantOwned;

final class Widget extends Model implements TenantOwned
{
    use BelongsToTenant;

    public function tenantColumn(): string
    {
        return 'org_id';
    }
}
```

## Implementing an AssertionValidator

Federation deliberately leaves the SAML/OIDC signature validation to you, behind one contract,
so you can wrap a **vetted, maintained** library rather than hand-rolling XML-signature or JWT
verification (that's how XSW/XXE/alg-confusion breaches happen).

```php
use Cbox\Id\Federation\Contracts\AssertionValidator;
use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;

final class SamlAssertionValidator implements AssertionValidator
{
    public function __construct(private readonly Connections $connections) {}

    public function validate(Connection $connection, string $rawResponse): FederatedPrincipal
    {
        $config = $this->connections->config($connection); // decrypted IdP config

        // Delegate to a vetted library (e.g. onelogin/php-saml), configured from $config,
        // which verifies the signature, audience, conditions and timestamps and parses XML
        // with external entities disabled. It MUST throw on anything it can't fully trust.
        $assertion = /* ...validate with the library... */;

        return new FederatedPrincipal(
            provider: 'saml',
            subject: $assertion->nameId(),
            email: $assertion->attribute('email'),
            name: $assertion->attribute('displayName'),
            connectionId: $connection->id,
            raw: $assertion->all(),
        );
    }
}
```

Bind it, then feed the trusted principal to `FederationFlow::completeLogin()` — the rest of the
login (user, membership, session, events, audit) is provider-agnostic and already built.

```php
$this->app->singleton(AssertionValidator::class, SamlAssertionValidator::class);
```

## Custom crypto / storage backends

The kernel contracts are pluggable too:

- `SecretBox` — swap libsodium for a KMS/HSM-backed sealer for managed deployments.
- `KeyManager` — back signing keys with an external key store.
- `RelationshipStore` — replace the Postgres ReBAC engine if you ever outgrow it.

All keep the same contract, so the modules above them don't change.
