---
title: Decisions endpoint
description: POST /oauth/decisions — ReBAC tuples, entitlements, and app-scoped RBAC permission checks; request and response shapes, and every refusal
weight: 2
---

# Decisions endpoint

`POST /oauth/decisions` answers authorization questions **live**: a revoked role, a
suspended organization or a flipped capability gate shows on the very next call, with no
new token. The caller authenticates with an access token (Bearer, or DPoP for a
sender-constrained one) audienced for this issuer. Background and the in-process
equivalent: [Authorization & the decision plane](../core-concepts/authorization.md).

A request is in one of two modes. They are not mixed: a body with `permission` and
`permissions` or `entitlements` is refused.

## ReBAC mode — tuples and entitlements

For relationship checks on resources and the organization's entitlements. The subject and
organization come from the token; a token with no `org` is refused with
`422 no_organization_context`.

```http
POST /oauth/decisions
Authorization: Bearer <access token>

{ "permissions": [ {"relation": "manage", "resource": "ticket:42"} ],
  "entitlements": [ "feature.sso", "seats" ] }
```

```json
{ "subject": {"type": "user", "id": "alice"},
  "organization": "org_x",
  "permissions": [ {"relation": "manage", "resource": "ticket:42", "allowed": true} ],
  "entitlements": { "feature.sso": {"value": {"enabled": true}, "mode": "decision_api", "source": "billing", "version": 3}, "seats": null } }
```

## RBAC mode — "may X do `feature:action` in org T"

For the roles and permissions an app declared in its manifest. The answer is the one a
token minted for the **calling app** right now would carry in its `permissions` claim:
grants in the organization, grants rolled down from its ancestor organizations, and
environment-wide grants all count; another app's roles never do.

### Request

| Field | Type | |
|---|---|---|
| `permission` | string, or list of strings | Required. The permission key(s) to check, as declared (`invoices:approve`). At most `cbox-id.oauth.decisions.max_batch` (default 50). |
| `subject` | string | The user to ask about. Required with a client token; optional (and must be the token's own `sub`) with a user token. |
| `org` | string | The organization. With a user token, optional and must equal the token's `org`. With a client token, the organization to ask about; omitted means environment-wide grants only. |

Who may ask about whom is decided from the token, not the body:

- **A user token** answers for its own subject in the organization it was issued for (or
  environment-wide, if it carries no `org`). Naming another `subject` or another `org` is
  refused. `decisions:read` is required only when the deployment sets
  `cbox-id.oauth.decisions.require_scope`.
- **A client token** (`client_credentials`, where `sub` is the client) may name any
  `subject`. It must carry the `decisions:read` scope, always — asking about somebody else
  is a wider question than asking about yourself. A client that an organization owns may
  only ask about that organization, and not environment-wide.

```http
POST /oauth/decisions
Authorization: Bearer <client_credentials token with decisions:read>

{ "permission": ["invoices:read", "invoices:approve"],
  "subject": "01J…",
  "org": "01J…" }
```

### Response

```json
{
  "mode": "rbac",
  "subject": {"type": "user", "id": "01J…"},
  "organization": "01J…",
  "client_id": "cid_01J…",
  "org_role": "admin",
  "organization_active": true,
  "allowed": false,
  "results": [
    {"permission": "invoices:read", "allowed": true},
    {"permission": "invoices:approve", "allowed": false}
  ]
}
```

- `allowed` is true only when **every** requested permission is held.
- `results` is in request order, one entry per distinct key.
- `org_role` is the subject's active membership tier in the organization, or `null` — an
  environment-wide grant is not a membership.
- `organization_active` is `false` when the organization is suspended or archived; every
  result is then `false`, whatever the subject holds.

### Refusals

| Status | `error` | When |
|---|---|---|
| 401 | `invalid_token` | No token, an inactive one, a DPoP mismatch, a token audienced elsewhere, or a token naming no subject or client. |
| 403 | `insufficient_scope` | A client token without `decisions:read`; a user token without it where the deployment requires it. |
| 403 | `access_denied` | A user token naming another subject or organization; an organization-owned client asking about another organization or environment-wide. |
| 422 | `invalid_request` | `permission` missing, empty or not strings; mixed with `permissions`/`entitlements`; a client token without `subject`. |
| 422 | `batch_too_large` | More permission keys than the configured cap. |

In PHP, the same answer comes from the `PermissionDecisions` contract:

```php
use Cbox\Id\AccessControl\Contracts\PermissionDecisions;

$decision = app(PermissionDecisions::class)->decide($userId, $organizationId, $clientId, ['invoices:approve']);

$decision->allowed();           // bool
$decision->organizationRole;    // ?MembershipRole
```
