---
title: OAuth clients (apps)
description: Registering apps, overlapping secret rotation, access-token lifetimes, grants, blueprints and the audited lifecycle
weight: 17
---

# OAuth clients (apps)

An OAuth client — an *app* in the console's vocabulary — is anything that asks this server
for tokens: a web app signing people in, a CLI, a service calling an API. Clients are
environment-owned: one registered in staging does not exist in production.

Everything below goes through one contract, `Cbox\Id\OAuthServer\Contracts\ClientRegistry`.
Resolve the client your caller may act on first (the registry acts on the client it is
handed; authorization is yours), then call the registry.

## Register

```php
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;

$registered = app(ClientRegistry::class)->register(new NewClient(
    name: 'Billing',
    redirectUris: ['https://billing.example.com/callback'],
    grantTypes: ['authorization_code', 'refresh_token'],
    scopes: ['openid', 'profile', 'email'],
    organizationId: $org->id,          // null = owned by the environment
    accessTokenTtl: 600,               // null = the deployment default
), AuditActor::organizationMember($memberId));

$registered->client->client_id;   // cid_…
$registered->secret;              // csec_… — shown ONCE, only its hash is stored
```

A confidential client gets a secret unless it registers a JWK Set (`jwks`), in which case
it authenticates with `private_key_jwt` and holds no secret at all — one credential
mechanism, never two. A public client (PKCE) holds none.

The registry refuses settings the token endpoint would refuse later
(`InvalidClientMetadata`, with the reason in the message):

- a grant that is not one of `authorization_code`, `refresh_token`, `client_credentials`,
  `urn:ietf:params:oauth:grant-type:device_code`, `urn:openid:params:grant-type:ciba`,
  `urn:ietf:params:oauth:grant-type:token-exchange` (`Enums\GrantType`);
- token exchange (RFC 8693) on a **public** client — the token endpoint requires client
  authentication for it;
- an `access_token_ttl` outside the bounds below;
- a `tokenEndpointAuthMethod` that contradicts the client type or the key set.

## Secrets and overlapping rotation

A client may hold several live secrets at once. Any live one authenticates; each is compared
in constant time, and all of them are compared on every attempt.

```php
$registry = app(ClientRegistry::class);

// Mint a new secret; the current ones keep working for one more hour.
$rotated = $registry->rotateSecret($client, graceSeconds: 3600, actor: $actor);

$rotated->secret;             // the new csec_… — shown once
$rotated->previousExpireAt;   // when the old ones stop working

$registry->secrets($client);  // list<ClientSecretSummary>: id, hint, created, expires, last used
$registry->revokeSecret($client, $secretId, $actor);   // cut one off now
```

The rollout this is for: rotate with a grace period, deploy the new secret everywhere, watch
the old secret's `lastUsedAt` stop moving, then either let it expire or revoke it.

- **Grace 0** retires the old secrets immediately — the emergency path.
- The grace is bounded by `cbox-id.oauth.client_secrets.max_rotation_grace`
  (default 30 days), so a rotation cannot leave the old credential alive indefinitely.
- A rotation **never extends** a secret already due to expire sooner.
- `hint` is the last four characters of the secret, so an operator can tell which one a
  deployment holds. Secrets that predate 1.19 have no hint — the plaintext was never kept.
- `lastUsedAt` is written at most once a minute.

Refusals throw `ClientSecretRefused`, whose `reason` (`Enums\ClientSecretRefusal`) says which:
a public client (`PublicClient`), a `private_key_jwt` client — rotating would add a bearer
credential to an asymmetric-only client (`SignsAssertions`), a grace out of range
(`GraceOutOfRange`), a secret id that is not a live secret of *this* client
(`UnknownSecret`), and revoking the last live secret of a shared-secret client
(`LastLiveSecret`) — rotate instead, or delete the client.

## Access-token lifetime

A client's `access_token_ttl` sets the lifetime of the access tokens **and** ID tokens it
is issued, on every grant. Null means the deployment default
(`cbox-id.oauth.access_token_ttl`, 900 s).

It is bounded by `cbox-id.oauth.max_access_token_ttl` (default 86 400 s) and a floor of
60 s. A value outside the bounds is refused when it is set; a client already above a
lowered ceiling is clamped to it on its next token. Pick the TTL from the revocation story:
a token a resource server validates offline can only be revoked by expiry.

## Changing an app's settings

`update()` takes the app's full settings as a `ClientBlueprint`: read the current one,
change what you mean to, hand it back.

```php
$settings = $registry->blueprint($client)
    ->withName('Billing (EU)')
    ->withGrantTypes(['client_credentials', 'urn:ietf:params:oauth:grant-type:token-exchange'])
    ->withAccessTokenTtl(300);

$registry->update($client, $settings, $actor);
```

The client type and authentication method cannot change here — they decide what credential
the client holds. Register a new client instead. An update that changes nothing records
nothing.

## Blueprints: promote an app between environments

A blueprint is an app's configuration without its identity or credentials — see
[Promote an app between environments](../cookbook/promote-an-app-between-environments.md).

## The audit trail

The registry records the lifecycle itself, so every console built on it gets the same
entries:

| Action | When | Context |
| --- | --- | --- |
| `app.created` | `register()`, `import()` | client type, grants; `source: blueprint` on import |
| `app.updated` | `update()`, RFC 7592 update | `changes`: each changed field, from → to |
| `app.secret_rotated` | `rotateSecret()` | new secret id and hint, grace, when the old ones expire |
| `app.secret_revoked` | `revokeSecret()` | secret id and hint |
| `app.deleted` | `delete()`, RFC 7592 delete | — |

The target is the public `client_id`. An app an organization owns is recorded on that
organization's trail; an environment-owned app on the system trail. Pass an `AuditActor`
for who asked — without one the entry names the system. Hints appear in the trail; secrets
and their hashes never do.

## Dynamic registration (RFC 7591 / 7592)

Self-registered clients go through the same rules. An RFC 7592 update that moves a client to
`none` or `private_key_jwt` revokes its secrets; moving back to a secret method mints a fresh
one rather than resurrecting the old. Both are recorded as `app.updated` with the client
itself as the actor.
