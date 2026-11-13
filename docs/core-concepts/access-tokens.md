---
title: Access token reference
description: Every claim on an access token, when it is present, and how the audience is chosen
weight: 18
---

# Access token reference

Access tokens are JWTs (RFC 9068) signed by the environment's active key and published at
`/.well-known/jwks.json`. The JOSE header carries `typ: at+jwt`, so a resource server can
refuse an ID Token presented in its place. Every grant — authorization code, refresh,
client credentials, device, CIBA and token exchange — mints through the same
`TokenIssuer`, so the shape below does not depend on how the token was obtained.

## Claims

| Claim | Present | Value |
|---|---|---|
| `iss` | always | The environment's issuer URL (matches discovery). |
| `sub` | always | The user's subject id; for `client_credentials`, the client id. |
| `client_id` | always | The client the token was issued to. |
| `aud` | always | See [Audience](#audience). |
| `scope` | always | Space-separated granted scopes (may be empty). |
| `jti` | always | Unique id; recorded so the token can be revoked and introspected. |
| `iat`, `exp` | always | Issued-at and expiry. Lifetime is the client's `access_token_ttl`, else `cbox-id.oauth.access_token_ttl` (900 s); a token whose scopes exactly match a `cbox-id.oauth.scope_token_ttls` entry (by default `account:apps:read`, 12 h) gets that entry's lifetime instead. Always capped by `max_access_token_ttl`. |
| `org` | always | The organization the grant is bound to, or `null`. |
| `org_name` | when `org` is set | The organization's display name. |
| `roles`, `permissions` | user tokens with any grant | The person's roles and their permissions for one app — the API's linked app when the token is for a [registered API](apis-and-scopes.md) that names one, otherwise the requesting client's. Environment-wide grants count when no organization is bound. Absent on `client_credentials`. |
| `feature_flags` | with the `feature_flags` scope | The sorted keys of every [feature flag](feature-flags.md) on for the subject in `org`; an empty list when none is. A `client_credentials` token is evaluated for its organization. |
| `ent`, `ent_ver` | when the org has Claims-mode entitlements | Embedded capability gates and the highest version among them. |
| `cnf.jkt` | DPoP-bound tokens | RFC 9449 key thumbprint; `token_type` is then `DPoP`. |
| `auth_time`, `acr` | user grants with a recorded login | RFC 9470 §6.1: when the person signed in, and the class reached (`urn:cbox-id:aal1`/`aal2`, derived from the login's `amr`). Authorization code and its refreshes carry both, always the original login's values. CIBA carries `auth_time` only. Device, token exchange, support-session and `client_credentials` tokens carry neither. See [Require step-up authentication](../cookbook/require-step-up-authentication.md). |
| custom | when a `TokenMinting` hook adds them | Hooks can add claims but never overwrite the ones above. |

## Audience

`aud` is decided once per token by the audience resolver:

| Situation | `aud` |
|---|---|
| No `resource`, no registered API scope | the issuer (RFC 9068 §2.2 requires an audience) |
| `resource` that is not a registered API | that URI, verbatim; registered API scopes are dropped from the token |
| `resource` naming a registered API, or no `resource` and the scopes belong to exactly one API | the API's identifier — or `[identifier, issuer]` when the token carries `openid`, so UserInfo still accepts it |
| No `resource` and scopes of more than one API | refused: `invalid_target` |

When a token is for a registered API its `scope` holds only that API's scopes plus the
protocol scopes (`openid`, `profile`, `email`, `offline_access`, `organizations`,
`groups`, `feature_flags`). The rules and the ownership model are in [APIs and scopes](apis-and-scopes.md).

A refresh re-mints the scopes and audience the original token was granted, never more.

## Verifying one

A resource server should check `iss`, the signature against the JWKS, `typ: at+jwt`, `exp`,
that its own identifier is in `aud`, and the scopes or permissions it needs. A string `aud`
and an array `aud` are both valid JWT; compare by membership.

Every token an app holds carries that app's `client_id`, including one issued to a person
signed in through it. Do not treat `client_id` as the caller's identity on its own. Only a
machine token (`client_credentials`) acts as the app: active, `sub` equal to `client_id`,
and no `act` claim. `Introspection::isMachine()` checks all three:

```php
if ($token->isMachine()) {
    // The app itself: its own secrets, its own grants, service-to-service questions.
} else {
    // A person ($token->subject), through that app. Hold them to their own access.
}
```

## Resource-server introspection

A confidential client can introspect its own tokens at `/oauth/introspect`. A resource
server accepting tokens minted to another client needs an explicit host-side grant:

```php
// config/cbox-id.php, within oauth.introspection:
'resource_servers' => [
    'registered-resource-client-id' => ['https://api.example.com'],
],
```

The default is an empty map. Register the API audience and confidential client normally;
then an operator grants only the exact audience that server owns. API-to-app RBAC linkage
(`oauth_apis.client_id`) does not grant introspection access. This map is not a dynamic
client-registration field. No wildcard, URI-prefix, issuer-audience or multi-audience
matching is performed.

The caller authenticates using its own confidential-client credentials and sends the
original access token as `token`. A valid grant returns the normal introspection response,
including the original `client_id`, subject, audience, token type and authentication
context. The resource server must still check its audience, required scopes, caller
integration delegation and current application permissions. A DPoP token's `cnf` must
be enforced; an introspection grant does not convert it into an ordinary bearer.

Cross-client introspection also checks current organization status and, for user tokens
bound to an organization, active membership. Removed or suspended members and inactive
organizations return only `{"active": false}`. Organization-owned resource clients cannot
inspect another organization's token. Environment scoping and token revocation remain
in force. Removing a configured grant stops subsequent cross-client introspection without
revoking the original client's token. Own-token introspection behavior is unchanged.

The `ResourceIntrospectionAccess` contract can be rebound by hosts that keep these
explicit grants in another authoritative store.
