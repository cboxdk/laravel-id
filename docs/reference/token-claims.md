---
title: Token claims
description: Every claim on the access token, the ID token and UserInfo — including org_role, the member's tier in the bound organization
weight: 1
---

# Token claims

Three places carry claims about a signed-in person: the **access token** (an RS256
`at+jwt`, RFC 9068), the **ID token** (OIDC Core, only when `openid` was granted) and the
**UserInfo** response (`GET|POST /oauth/userinfo`, requires `openid`). The table says which
claim appears where; the notes below say when.

| Claim | Access token | ID token | UserInfo | Meaning |
|---|---|---|---|---|
| `iss` | yes | yes | — | The environment's issuer. |
| `sub` | yes | yes | yes | The user id; on a `client_credentials` token, the client id. |
| `aud` | yes | yes | — | Access token: the RFC 8707 `resource`, else the issuer. ID token: the client id. |
| `client_id` | yes | — | — | The client the token was minted for. |
| `scope` | yes | — | — | Space-separated granted scopes. |
| `jti`, `iat`, `exp` | yes | `iat`, `exp` | — | Identifier and lifetime. The ID token lives as long as the access token. |
| `org` | when bound | when bound | when bound | The organization the grant is bound to. |
| `org_name` | when bound | when bound | when bound | That organization's display name. |
| `org_role` | when bound + member | when bound + member | when bound + member | The subject's membership tier in `org`: `owner`, `admin`, `developer`, `member` or `viewer`. |
| `roles` | when held | — | when held | The app's role keys the subject holds (this app's roles plus organization-wide roles). |
| `permissions` | when held | — | when held | The union of those roles' permission keys. |
| `groups` | — | with `groups` scope | — | The same role keys, under the name ID-token consumers (Kubernetes, Grafana, Vault) read. |
| `organizations` | — | — | with `organizations` scope | Every active membership: `[{id, name, role}]`. |
| `ent`, `ent_ver` | when configured | — | — | Claims-mode entitlements and their version. See [Entitlements & billing](../core-concepts/entitlements-and-billing.md). |
| `cnf` | DPoP-bound | — | — | `{"jkt": …}`, the RFC 9449 key thumbprint. |
| `nonce`, `auth_time`, `amr`, `acr`, `at_hash` | — | yes | — | OIDC authentication context. |
| `email`, `email_verified` | — | — | with `email` scope | |
| `name` | — | — | with `profile` scope | |

## `org_role` — the membership tier

`org_role` tells an app whether the person is the organization's owner, an admin or
somebody with less, without a second call. It is the
[`MembershipRole`](../core-concepts/organization-access.md#ordered-membership-roles) of
`sub` in `org`.

- **Present** whenever an organization is bound AND the subject holds an **active**
  membership in it.
- **Absent** on a `client_credentials` token (no person behind it), on a token with no
  `org`, for a subject with no membership, and for a membership that is invited or
  suspended — a suspended owner is not an owner to a relying party.
- **Every user grant carries it**: authorization code, refresh token, device code (RFC 8628),
  CIBA and token exchange (RFC 8693) all mint through the same issuer.
- **Freshness.** The access token and ID token carry the tier at the moment they were
  minted; a refresh re-reads it, so an ownership transfer shows in the next token. UserInfo
  reads it live on every call.
- **Not forgeable by a hook.** `org_role` is a reserved claim: a
  [token-minting action](../core-concepts/external-actions.md) that returns it is ignored.

`org_role` is the tier, not the permission set. It answers "is this the owner?" — for
"may this person approve invoices?" use `permissions`, or ask the
[decisions endpoint](decisions.md) live.

```json
{
  "iss": "https://acme.id.example",
  "sub": "01J…",
  "client_id": "cid_01J…",
  "scope": "openid profile",
  "org": "01J…",
  "org_name": "Acme",
  "org_role": "admin",
  "roles": ["billing-admin"],
  "permissions": ["invoices:read", "invoices:approve"],
  "aud": "https://acme.id.example",
  "iat": 1790000000,
  "exp": 1790000900
}
```

## Reserved claims

A token-minting hook can add claims but can never set or overwrite `iss`, `sub`,
`client_id`, `jti`, `scope`, `org`, `org_name`, `org_role`, `iat`, `exp`, `nbf`, `aud`,
`cnf`, `ent`, `ent_ver`, `typ`, `roles` or `permissions`.
