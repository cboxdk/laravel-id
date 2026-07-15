---
title: Provision users to a downstream app
description: Register a downstream SCIM 2.0 connection and push user/membership changes out to it
weight: 9
---

# Provision users to a downstream app

This recipe wires the platform to push users OUT to a downstream SaaS app over its
SCIM 2.0 endpoint. See [Outbound SCIM provisioning](../core-concepts/outbound-provisioning.md)
for the mental model.

## 1. Register a connection

Resolve `Cbox\Id\Provisioning\Contracts\ProvisioningConnections` and register the
target. The secret (a bearer token, or an OAuth client secret) is sealed at rest
and never returned again; the base URL is SSRF-checked before it is stored.

```php
use Cbox\Id\Provisioning\Contracts\ProvisioningConnections;
use Cbox\Id\Provisioning\Enums\AuthScheme;
use Cbox\Id\Provisioning\Enums\DeprovisionPolicy;

$registered = app(ProvisioningConnections::class)->register(
    organizationId: null,                               // null = environment-wide
    name: 'Acme Helpdesk',
    baseUrl: 'https://acme.example.com/scim/v2',
    authScheme: AuthScheme::Bearer,
    secret: $bearerTokenFromAcme,                        // sealed at rest
    attributeMapping: [],                                // [] = sensible defaults
    organizationIds: [],                                 // scope: empty = every subject
    deprovisionPolicy: DeprovisionPolicy::Deactivate,    // or ::Delete
);
```

Scope it to organizations instead by passing `organizationIds: [$orgId, ...]`;
only members of those organizations are then provisioned.

### OAuth 2.0 client-credentials

For an app that wants a short-lived token, use the client-credentials grant — the
platform exchanges the sealed client secret at the token endpoint for a bearer
(standard HTTP client, no hand-rolled OAuth):

```php
app(ProvisioningConnections::class)->register(
    organizationId: null,
    name: 'Acme (OAuth)',
    baseUrl: 'https://acme.example.com/scim/v2',
    authScheme: AuthScheme::OAuth2ClientCredentials,
    secret: $clientSecret,
    authConfig: [
        'token_url' => 'https://idp.acme.example.com/oauth/token',
        'client_id' => 'cbox-provisioning',
        'scope' => 'scim',
    ],
);
```

## 2. Changes flow automatically

Once a connection exists, every relevant domain event enqueues an operation:
`user.created`/`user.updated` → create-or-update, `user.deactivated` → `active`
= false, `organization.member_added`/`member_removed` → provision/de-provision.
The listener only enqueues; the scheduled drain delivers.

Make sure the scheduler is running (`schedule:run` every minute) so the outbox
drains — or drive it yourself:

```bash
php artisan cbox-id:provisioning:drain     # dispatch a drain per active connection
```

## 3. Backfill / reconcile existing users

When you add a connection to an environment that already has users, reconcile so
the downstream app catches up:

```bash
php artisan cbox-id:provisioning:sync --connection=01J...       # one connection
php artisan cbox-id:provisioning:sync                           # every connection
```

`sync` enqueues an upsert for every in-scope subject and delivers immediately,
inside each connection's reconstructed environment.

## Testing

Dogfood `Cbox\Id\Provisioning\Testing\InteractsWithProvisioning` and the in-memory
`FakeScimClient`:

```php
$fake = $this->fakeScimClient();
$connection = $this->registerProvisioningConnection()->connection;

$user = $this->makeUser('alice@example.com', 'Alice');
$this->relayEvents();                       // fire the listener
$this->drainProvisioning($connection->id);  // deliver (reconstructs the env)

expect($fake->requestsOfType('create'))->toHaveCount(1);
```
