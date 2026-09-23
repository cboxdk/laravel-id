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
| `iat`, `exp` | always | Issued-at and expiry. Lifetime is the client's `access_token_ttl`, else `cbox-id.oauth.access_token_ttl` (900 s). |
| `org` | always | The organization the grant is bound to, or `null`. |
| `org_name` | when `org` is set | The organization's display name. |
| `roles`, `permissions` | user tokens with any grant | The person's roles and their permissions for one app — the API's linked app when the token is for a [registered API](apis-and-scopes.md) that names one, otherwise the requesting client's. Environment-wide grants count when no organization is bound. Absent on `client_credentials`. |
| `ent`, `ent_ver` | when the org has Claims-mode entitlements | Embedded capability gates and the highest version among them. |
| `cnf.jkt` | DPoP-bound tokens | RFC 9449 key thumbprint; `token_type` is then `DPoP`. |
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
`groups`). The rules and the ownership model are in [APIs and scopes](apis-and-scopes.md).

A refresh re-mints the scopes and audience the original token was granted, never more.

## Verifying one

A resource server should check `iss`, the signature against the JWKS, `typ: at+jwt`, `exp`,
that its own identifier is in `aud`, and the scopes or permissions it needs. A string `aud`
and an array `aud` are both valid JWT; compare by membership.
