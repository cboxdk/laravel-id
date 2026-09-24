---
title: APIs and scopes
description: Register the resource servers your tokens are for, who owns each scope, and how every token's audience, scope and roles are decided
weight: 17
---

# APIs and scopes

An **API** is a resource server: something that receives access tokens and decides what
the caller may do. Registering one tells the authorization server three things it could
not know before:

- **its identifier** — the absolute URI that goes into a token's `aud`, and that a client
  names with the RFC 8707 `resource` parameter;
- **the scopes it owns** — `tax:read`, `tax:assess` — and which of them organizations may
  request;
- **which app's roles it enforces** — optionally, the client whose declared roles and
  permissions a token for this API should carry.

Scopes that no API owns keep working exactly as before. Registration is opt-in per scope:
an environment that registers no APIs issues byte-for-byte the tokens it always did.

## Why this exists

Without it a scope is free text on each client. Anyone who can edit a client — an
organization administrator in a multi-tenant console, a self-registered MCP client — can
type `tax:assess` onto it, ask for a token with `resource=https://tax.example.com`, and
receive a signed token whose `aud` and `scope` say exactly what the tax API is waiting to
read. The resource server checks `aud` (as RFC 9068 tells it to) and the scope, and both
pass. A registered API closes that: its scopes can only be held by the clients its owner
allows, and a free-text scope can never ride on its audience.

## The model

```
Environment
 ├─ API  identifier=https://tax.example.com   owner=environment   app=cid_tax
 │   ├─ tax:read     tenant_requestable = true
 │   └─ tax:assess   tenant_requestable = false
 └─ API  identifier=https://books.acme.test   owner=org Acme
     └─ books:read
```

| Field | Meaning |
|---|---|
| `identifier` | Absolute URI with a host, no fragment, ≤ 255 characters. Unique per environment. Immutable — tokens already carry it. |
| `name` | What a person calls it. |
| `organization_id` | The owner. `null` = the environment owns it. |
| `client_id` | Optional. The app whose declared roles/permissions this API enforces. Must have the **same owner** as the API. |
| scope `key` | An RFC 6749 scope token (≤ 128 characters). **Unique per environment**, across all APIs — a request names a scope by key alone. The protocol scopes (`openid`, `profile`, `email`, `offline_access`, `organizations`, `groups`) can never be registered. |
| scope `tenant_requestable` | For an environment-owned API: may a client owned by an organization (or a dynamically registered one) hold this scope? Default `true`. |

## Who may hold a registered scope

One rule, applied when a client is saved and again when a token is minted:

| The client is… | It may hold a scope of… |
|---|---|
| environment-owned (`organization_id` null, created by an operator) | any API |
| owned by organization *X* | an API owned by *X*; or an environment-owned API's **tenant-requestable** scopes |
| dynamically registered (RFC 7591) | an environment-owned API's **tenant-requestable** scopes |

A dynamically registered client has a null owner, like an operator's own client, but it is
never treated as environment-owned: whoever reached `/oauth/register` registered it.

**On save.** `Client` refuses to be saved holding a registered scope its owner may not
hold, and throws `ScopeNotGrantable` (with `$e->scopes` listing them). This runs for every
writer — the registry, dynamic registration, service accounts, and a console that sets
`$client->scopes` and calls `save()`. On an update only the scopes being **added** are
judged, so a client that held a free-text key before an API registered it stays editable;
changing the owner or becoming dynamically registered re-judges everything it holds.

**At issuance.** Rows written before the API existed still hold the scope. The token
endpoint drops it (see below), so the squatted value is worthless.

## How a token's audience is decided

Every access token — authorization code, refresh, client credentials, device, CIBA and
token exchange — is minted by `TokenIssuer`, which asks one `AudienceResolver` per token.
Starting from the scopes the client is registered for:

1. **Nothing registered involved.** No scope belongs to an API and `resource` (if sent)
   names none: the token is exactly what it was before APIs existed — `aud` is the
   `resource` or the issuer, scopes unchanged, the requesting client's roles.
2. **Ownership.** Registered scopes the client may not hold are dropped.
3. **Pick the API.** The one `resource` names; or, with no `resource`, the single API the
   remaining registered scopes belong to. Scopes of **two** APIs and no `resource` is
   `invalid_target` — name one.
4. **Narrow.** With an API chosen, the token carries that API's scopes plus the protocol
   scopes. Free-text scopes and other APIs' scopes are dropped. With `resource` naming an
   unregistered URI, registered scopes are dropped instead — a registered scope is only
   ever valid at its own API.
5. **Refuse an empty result.** If scopes were requested and none survive: `invalid_scope`.

The token then gets:

| Claim | Value |
|---|---|
| `aud` | The API's identifier. `[identifier, issuer]` when the token also carries `openid`, so UserInfo keeps accepting it. |
| `scope` | The narrowed set. The token response echoes it whenever it differs from the request (RFC 6749 §5.1). |
| `roles` / `permissions` | From the API's linked app (`client_id`) when set; otherwise the requesting client's, as before. |

The ID Token and UserInfo describe the person to the **requesting** client, so their
`groups` / `roles` still come from the requesting client's app.

**Refresh never widens.** A refresh token records the access token's granted scopes and
resolved audience, not the request. A refresh re-mints what was granted — even if the API
later makes another scope tenant-requestable.

## Registering an API

```php
use Cbox\Id\OAuthServer\Contracts\Apis;
use Cbox\Id\OAuthServer\ValueObjects\{ApiScopeDefinition, NewApi};

$api = app(Apis::class)->register(new NewApi(
    identifier: 'https://tax.example.com',
    name: 'Tax',
    organizationId: null,            // environment-owned
    clientId: $taxApp->client_id,    // stamp the tax app's roles into tokens for this API
    scopes: [
        new ApiScopeDefinition('tax:read', 'Read returns'),
        new ApiScopeDefinition('tax:assess', 'Assess returns', tenantRequestable: false),
    ],
));

app(Apis::class)->defineScope($api, new ApiScopeDefinition('tax:file'));   // add or update
app(Apis::class)->removeScope($api, 'tax:file');
app(Apis::class)->linkClient($api, null);
```

Every refusal is an `InvalidApiDefinition` whose message names the field and the reason.
In tests, `InteractsWithOAuth::makeApi('https://tax.example.test', ['tax:read', 'tax:assess' => false])`
registers one in a line.

Deleting an API deletes its scopes. Clients that held those keys keep them as free text;
tokens already minted keep their `aud` until they expire.

## Requesting a token for an API

```http
POST /oauth/token
grant_type=client_credentials&scope=tax:read&resource=https://tax.example.com
```

```json
{ "aud": "https://tax.example.com", "scope": "tax:read", "client_id": "cid_…" }
```

`resource` is optional when the requested scopes belong to one API. For the authorization
code grant, send `resource` at `/authorize` (the code is bound to it) or at the token
endpoint. Errors are standard: `invalid_target` (RFC 8707 §2) for an ambiguous or unusable
audience, `invalid_scope` (RFC 6749 §5.2) when nothing requested may be granted.

## Discovery and dynamic registration

- **Discovery** (`scopes_supported`) lists the protocol scopes followed by the scopes any
  client in the environment may hold — tenant-requestable scopes of environment-owned APIs.
  Private scopes and tenant APIs are not advertised.
- **Dynamic registration** accepts exactly those registered scopes. The
  `dynamic_registration.allowed_scopes` allow-list keeps governing scopes no API owns, and
  listing a registered scope there cannot widen what its API allows. Anything else is
  dropped, and the response's `scope` says what was kept.

## Scope and limits

- `resource` is single-valued; a repeated `resource` parameter is not supported.
- Identifiers match byte-for-byte. `https://tax.example.com` and `https://tax.example.com/`
  are different APIs.
- Who may register an API, and under which identifiers, is the host's policy. The registry
  enforces uniqueness and ownership, not that an organization owns the domain it names.

See also: [Access token reference](access-tokens.md) ·
[Authorization & the decision plane](authorization.md) ·
[Standards conformance](../security/standards.md).
