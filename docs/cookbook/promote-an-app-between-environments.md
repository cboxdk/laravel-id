---
title: Promote an app between environments
description: Export an app's configuration from staging as a versioned blueprint and create the same app in production, with its own id and secret
weight: 44
---

# Promote an app between environments

Client ids are minted per environment, so the app you configured in staging has no
counterpart in production until you create one. A `ClientBlueprint` carries the
configuration across — and nothing that belongs to the environment it came from.

## What a blueprint carries

| Carried | Left out |
| --- | --- |
| name, client type, token-endpoint auth method | `client_id` — minted per environment |
| grants, scopes, first-party flag | secrets and the registration access token — credentials are never copied |
| redirect URIs, post-logout redirect URIs, manifest URL | the owning organization — an id in the source environment |
| access-token lifetime | the JWK Set — each environment should hold its own keys |

## Export

```php
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;

$json = app(ClientRegistry::class)->blueprint($stagingClient)->toJson();
```

```json
{
    "kind": "cbox-id.client-blueprint",
    "version": 1,
    "name": "Billing",
    "client_type": "confidential",
    "token_endpoint_auth_method": null,
    "grant_types": [
        "authorization_code",
        "refresh_token"
    ],
    "redirect_uris": [
        "https://billing.staging.example.com/callback"
    ],
    "post_logout_redirect_uris": [],
    "scopes": [
        "email",
        "openid",
        "profile"
    ],
    "first_party": false,
    "manifest_url": "https://billing.staging.example.com/cbox-id.json",
    "access_token_ttl": 600
}
```

The document is deterministic: keys in a fixed order, every list de-duplicated and sorted,
so the same app always exports the same bytes and a blueprint committed to a repository
diffs cleanly.

## Import

Run the import in the **target** environment, adjusting what names the source deployment:

```php
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;
use Cbox\Id\OAuthServer\ValueObjects\ClientBlueprint;

$blueprint = ClientBlueprint::fromJson($json)
    ->withRedirectUris(['https://billing.example.com/callback'])
    ->withManifestUrl('https://billing.example.com/cbox-id.json');

$registered = app(ClientRegistry::class)->import(
    $blueprint,
    organizationId: null,                 // or the owning organization in THIS environment
    actor: AuditActor::organizationMember($memberId),
);

$registered->client->client_id;   // a new cid_…
$registered->secret;              // a new csec_… — shown once
```

A `private_key_jwt` app is imported with the target environment's public key set:
`import($blueprint, jwks: $productionJwks)`. Without it the import is refused.

The import is recorded as `app.created` with `source: blueprint`.

## What is refused

`ClientBlueprint::fromJson()` / `fromArray()` refuse — never silently drop — anything they
cannot honour, with an `InvalidClientMetadata` naming the reason:

- an unknown key. A document carrying `client_secret` or `client_id` was written by
  somebody who expects them to be honoured;
- a `kind` other than `cbox-id.client-blueprint`, or a `version` this server does not read;
- an unknown client type, auth method or grant, or token exchange on a public client;
- a redirect URI that is not absolute, carries a fragment, or uses a single-word custom
  scheme (`javascript:`); an `authorization_code` app with no redirect URI;
- an access-token lifetime outside the configured bounds;
- values of the wrong type.

The target environment's own rules still apply on top: a console may hold redirect URIs to a
stricter bar (https only, say) before it calls `import()`.
