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
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;

$user = app(Subjects::class)->provisionFederated(
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
app(Roles::class)->grantPermission($reseller->id, $role->id, 'tickets.manage');
app(Roles::class)->assign($reseller->id, 'support_1', $role->id);

app(AccessChecker::class)->can('support_1', 'tickets.manage', $customer->id); // true (rolls down)
```

## Push capability gates from Stripe / Cashier

Wire your billing webhook to the entitlement writer. Billing translates the plan
into **capability gates** (Cbox ID never sees the plan itself). Use `reconcile()` to
guard against dropped webhooks — it upserts what's present and revokes what's absent:

```php
use Cbox\Id\Kernel\Authorization\Contracts\EntitlementWriter;
use Cbox\Id\Kernel\Authorization\Enums\EnforcementMode;
use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementInput;

app(EntitlementWriter::class)->reconcile($org->id, [
    new EntitlementInput('feature.sso', ['enabled' => true]),                   // gate, from the plan
    new EntitlementInput('feature.export', ['enabled' => true]),
    new EntitlementInput('seats', ['limit' => 50], EnforcementMode::DecisionApi), // limit, checked live
], EntitlementSource::Billing);
```

Pick `EnforcementMode::Claims` for coarse, slow-changing gates (embedded in tokens),
and `EnforcementMode::DecisionApi` (the default) for anything that must revoke immediately.

> Keeping your own billing engine and want the full flow — reconcile, enforcement
> modes, provenance and events? See [Entitlements & billing](../core-concepts/entitlements-and-billing.md).

## Provision users over SCIM (inbound — an IdP → the platform)

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

## Provision users to a downstream app (outbound — the platform → a SaaS app)

The mirror direction: push the platform's user/membership changes OUT to an
organization's downstream apps over **their** SCIM endpoints. See the full recipe:
[Provision users to a downstream app](provision-users-to-a-downstream-app.md).

## Send a one-time passcode (email / SMS)

```php
use Cbox\Id\Otp\Contracts\OtpService;

$challenge = app(OtpService::class)->issue('login', 'sam@acme.test', 'email', request()->ip());
// ... user types the code they received ...
$result = app(OtpService::class)->verify($challenge->id, $code, request()->ip());
$result->verified; // true once, then single-use
```

Email works out of the box. To offer "text me a code", wire your SMS provider
behind the channel contract: [Add an SMS OTP channel](add-an-sms-otp-channel.md).

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

## Stream audit events to a customer's SIEM

Mirror one environment's hash-chained trail to Splunk, Elastic, Graylog or a CEF
collector — isolation intact, dedup by the entry hash. See the full recipe:
[Stream audit events to a SIEM](enable-an-audit-stream.md).
