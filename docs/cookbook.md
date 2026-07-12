---
title: Cookbook
description: Task-focused recipes for the common jobs
weight: 4
---

# Cookbook

Practical, copy-pasteable recipes. Each assumes you resolve contracts from the container.

## Central login across your products

Your products don't embed the package — they log in against the running instance and reconcile
identity. Server-side, provisioning a federated login is one call:

```php
use Cbox\Id\Identity\Contracts\UserDirectory;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;

$user = app(UserDirectory::class)->provisionFederated(
    new FederatedPrincipal('oidc', 'google|123', 'sam@acme.test', 'Sam'),
);
```

`provisionFederated` is idempotent per `(provider, subject)`: the first call creates the user
and the identity link; later calls return the same user.

## Set up a reseller → customer hierarchy

```php
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Contracts\OrganizationHierarchy;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Cbox\Id\Organization\Enums\OrganizationType;

$orgs = app(Organizations::class);
$reseller = $orgs->create(new NewOrganization('Contoso Partners', 'contoso', OrganizationType::Reseller));
$customer = $orgs->create(new NewOrganization('Northwind', 'northwind', parentId: $reseller->id));

$h = app(OrganizationHierarchy::class);
$h->manages($reseller->id, $customer->id);   // true — the reseller manages the customer
$h->descendants($reseller->id);              // ['<northwind id>']
```

A support role granted at the reseller now applies to the customer:

```php
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Contracts\AccessChecker;

$role = app(Roles::class)->define($reseller->id, 'support');
app(Roles::class)->grantPermission($role->id, 'tickets.manage');
app(Roles::class)->assign($reseller->id, 'support_1', $role->id);

app(AccessChecker::class)->can('support_1', 'tickets.manage', $customer->id); // true (rolls down)
```

## Push entitlements from Stripe / Cashier

Wire your billing webhook to the entitlement writer. Use `reconcile()` to guard against dropped
webhooks — it upserts everything present and revokes anything absent:

```php
use Cbox\Id\Kernel\Authorization\Contracts\EntitlementWriter;
use Cbox\Id\Kernel\Authorization\Enums\EnforcementMode;
use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementInput;

app(EntitlementWriter::class)->reconcile($org->id, [
    new EntitlementInput('plan', ['tier' => 'pro']),
    new EntitlementInput('seats', ['limit' => 50], EnforcementMode::DecisionApi),
    new EntitlementInput('feature.sso', ['enabled' => true]),
], EntitlementSource::Billing);
```

Pick `EnforcementMode::Claims` for coarse, slow-changing entitlements (embedded in tokens),
and `EnforcementMode::DecisionApi` for anything that must revoke immediately.

> Keeping your own billing engine and want the full flow — reconcile, enforcement
> modes, provenance and events? See [Entitlements & billing](entitlements-and-billing.md).

## Provision users over SCIM

```php
use Cbox\Id\Directory\Contracts\Directories;
use Cbox\Id\Directory\Contracts\DirectorySync;
use Cbox\Id\Directory\ValueObjects\ScimUser;

$registered = app(Directories::class)->register($org->id, 'Okta'); // token shown ONCE
$directory = $registered->directory;

app(DirectorySync::class)->provisionUser($directory->id, new ScimUser('okta|1', 'dana', 'dana@corp.com'));

// Deprovision drops membership AND kills the user's sessions immediately:
app(DirectorySync::class)->deprovisionUser($directory->id, 'okta|1');
```

## Register a webhook

```php
use Cbox\Id\Webhooks\Contracts\WebhookRegistry;

$registered = app(WebhookRegistry::class)->register($org->id, 'https://app.acme.test/hooks', [
    'organization.created', 'user.login', 'entitlement.updated',
]);
// $registered->secret is the HMAC signing secret — store it once; verify X-Cbox-Signature.
```

Delivered domain events fan out automatically; failures retry with exponential backoff.

## Verify the audit chain

```php
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;

$result = app(AuditLog::class)->verifyChain($org->id);
$result->valid;            // false if any entry was tampered, reordered or deleted
$result->brokenAtSequence; // where it broke

// Sign a checkpoint to anchor externally:
$checkpoint = app(AuditLog::class)->checkpoint($org->id);
```
