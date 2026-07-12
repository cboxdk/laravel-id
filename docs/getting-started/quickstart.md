---
title: Quickstart
description: From an empty app to an organization, a user, roles, entitlements and an SSO login
weight: 2
---

# Quickstart

Everything is resolved from the container behind a contract. Here's the whole platform in a
handful of calls.

## 1. Create an organization (a tenant)

```php
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Cbox\Id\Organization\Enums\OrganizationType;

$org = app(Organizations::class)->create(
    new NewOrganization('Northwind Traders', 'northwind', OrganizationType::Customer),
);
```

An organization **is** a tenant. Its `tenantKey()` is its id, and everything tenant-owned is
scoped to it automatically.

## 2. Create a user and add them to the org

```php
use Cbox\Id\Identity\Contracts\UserDirectory;
use Cbox\Id\Organization\Contracts\Memberships;

$user = app(UserDirectory::class)->create('ida@northwind.test', 'Ida', password: 's3cret');

app(Memberships::class)->add($org->id, $user->id, role: 'admin');
```

## 3. Grant a role and check access

```php
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Contracts\AccessChecker;

$role = app(Roles::class)->define($org->id, 'admin');
app(Roles::class)->grantPermission($role->id, 'members.invite');
app(Roles::class)->assign($org->id, $user->id, $role->id);

app(AccessChecker::class)->can($user->id, 'members.invite', $org->id); // true
```

## 4. Push an entitlement from billing

```php
use Cbox\Id\Kernel\Authorization\Contracts\EntitlementWriter;
use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;
use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementInput;

app(EntitlementWriter::class)->set(
    $org->id,
    new EntitlementInput('plan', ['tier' => 'pro']),
    EntitlementSource::Billing,
    sourceRef: 'sub_1Pk9',
);

app(EntitlementReader::class)->get($org->id, 'plan')?->string('tier'); // 'pro'
```

Every write is versioned, appended to history, emitted as an event and audited.

## 5. Complete an SSO login

Register a per-org connection, then hand a validated principal to the flow (the
[AssertionValidator](extending.md#implementing-an-assertionvalidator) turns a raw SAML/OIDC
response into that principal):

```php
use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\FederationFlow;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;

$connections = app(Connections::class);
$conn = $connections->create($org->id, ConnectionType::Saml, 'Okta', [/* idp config */]);
$connections->activate($conn->id);

$session = app(FederationFlow::class)->completeLogin(
    $conn,
    new FederatedPrincipal('saml', 'okta|ida', 'ida@northwind.test', 'Ida', $conn->id),
);
```

That provisions/links the user, ensures membership and starts a session — the same path SCIM,
password and social logins converge on.

## 6. Read the audit trail

```php
use Cbox\Id\AuditQuery\Contracts\AuditReader;
use Cbox\Id\AuditQuery\ValueObjects\AuditQueryFilter;

$page = app(AuditReader::class)->query(new AuditQueryFilter(organizationId: $org->id));
foreach ($page->items as $entry) {
    echo "{$entry->sequence}  {$entry->action}\n";
}
```

Next: [Architecture & patterns](../architecture.md).
