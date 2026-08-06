---
title: Inbound SCIM provisioning server
description: The SCIM 2.0 server at /scim/v2 — directory-scoped bearer auth, the full User and Group lifecycle, type-checked filters, and RFC 7644 error semantics
weight: 6
---

# Inbound SCIM provisioning server

The `Directory` module plus the SCIM controllers in `src/Api/Http/Controllers/Scim/`
make the platform a SCIM 2.0 **server**: a customer's identity provider pushes users
and groups **in** over HTTP, and the platform provisions local accounts, org
membership and — on deactivation or delete — session revocation from those pushes.

This is the opposite direction from
[outbound SCIM provisioning](outbound-provisioning.md), where the platform is the
SCIM *client* pushing to a downstream app's endpoint. Both share one vocabulary
source, `Cbox\Id\Scim\ScimSchema` (URNs, `ListResponse`, `PatchOp`, `Error`, `meta`).

## Endpoint surface

Everything is registered under `/scim/v2` by `Api\ApiServiceProvider`, inside the
environment-resolved IdP surface, behind
`ScimContentType → throttle:120,1 → AuthenticateScim`:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/scim/v2/ServiceProviderConfig` | What the server supports (RFC 7644 §4). |
| `GET` | `/scim/v2/ResourceTypes` | `User` and `Group` resource types. |
| `GET` | `/scim/v2/Schemas` | Core User, Enterprise User extension, Group. |
| `GET` | `/scim/v2/Users` | List, with `filter`, `startIndex`, `count`. |
| `POST` | `/scim/v2/Users` | Create (provision). |
| `GET` | `/scim/v2/Users/{id}` | Read one. |
| `PUT` | `/scim/v2/Users/{id}` | Full replace. |
| `PATCH` | `/scim/v2/Users/{id}` | Partial update (path and pathless forms). |
| `DELETE` | `/scim/v2/Users/{id}` | Deprovision. |
| `GET` | `/scim/v2/Groups` | List, with `filter`, `startIndex`, `count`, `attributes`. |
| `POST` | `/scim/v2/Groups` | Create. |
| `GET` | `/scim/v2/Groups/{id}` | Read one (members included by default). |
| `PUT` | `/scim/v2/Groups/{id}` | Full replace, including membership. |
| `PATCH` | `/scim/v2/Groups/{id}` | Rename and membership add/remove/replace. |
| `DELETE` | `/scim/v2/Groups/{id}` | Delete. |

There is no other SCIM route. The discovery endpoints are **authenticated** like the
rest — an unauthenticated `GET /scim/v2/ServiceProviderConfig` is a 401.

## Authentication and scoping

Each directory is registered per organization and gets exactly one bearer token:

```php
use Cbox\Id\Directory\Contracts\Directories;

$registered = app(Directories::class)->register($organization->id, 'Corporate IdP');

$registered->token;         // "scim_<64 hex chars>" — shown once, never retrievable
$registered->directory->id; // the directory the token authenticates
```

- The token is generated as `'scim_'.bin2hex(random_bytes(32))` and stored only as
  `hash('sha256', $token)` in `directories.bearer_token_hash`. The plaintext is
  returned once and is not recoverable; the package exposes no rotation call, so
  replacing a token means registering a directory again.
- `AuthenticateScim` reads `Authorization: Bearer …`, looks the SHA-256 hash up, and
  requires `status = active`. A miss returns a SCIM `Error` with `401` and
  `WWW-Authenticate: Bearer realm="SCIM"`.
- The resolved `Directory` is stashed on the request; every controller reads it and
  scopes every query to `directory_id`. A token therefore addresses exactly one
  directory — never another directory in the same organization.

### Environment isolation

`Directory`, `DirectoryUser` and `DirectoryGroup` are all `BelongsToEnvironment`, so
the token lookup itself is environment-scoped (see
[Environments](environments.md)). Presenting environment A's token on environment B's
host does not resolve a directory at all — it is a **401**, not a cross-tenant read.
Resource ids are equally scoped: a `GET`/`PATCH`/`PUT`/`DELETE` of another
environment's user id is a `404`, and its rows are invisible to `filter` queries.

## Media type

`ScimContentType` runs on the outside of the stack and stamps
`Content-Type: application/scim+json` on every non-empty response body, success or
failure. A `204 No Content` (a successful `DELETE`) keeps its empty body and no
content type. Requests are parsed as JSON; the server does not require the request
itself to carry the SCIM media type.

## Users

### List, filter, paginate

```bash
curl -sS 'https://id.example.com/scim/v2/Users?filter=userName%20eq%20%22sam%22' \
  -H 'Authorization: Bearer scim_…'
```

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "totalResults": 1,
  "startIndex": 1,
  "itemsPerPage": 1,
  "Resources": [
    {
      "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
      "id": "01J…",
      "externalId": "okta|1",
      "userName": "sam",
      "active": true,
      "displayName": "Sam Ito",
      "name": {"formatted": "Sam Ito", "givenName": "Sam", "familyName": "Ito"},
      "emails": [{"value": "sam@corp.com", "primary": true}],
      "meta": {
        "resourceType": "User",
        "created": "2026-07-25T09:12:44Z",
        "lastModified": "2026-07-25T09:12:44Z",
        "location": "https://id.example.com/scim/v2/Users/01J…"
      }
    }
  ]
}
```

- `startIndex` is 1-based and defaults to 1; `count` defaults to and is capped at
  **200** (`DatabaseDirectoryUsers::MAX_PAGE`). Results are ordered by `id`.
- `meta.created` / `meta.lastModified` are emitted as UTC (`…Z`) so a connector can
  run a delta sync off `meta.lastModified gt "<watermark>"` instead of a full sweep.
- `meta.location` is an **absolute** URI. Every single-resource response also carries
  `Content-Location` with the same value, and a `201` carries `Location` as well
  (RFC 7644 §3.1, §3.3).

### Create

```bash
curl -sS -X POST 'https://id.example.com/scim/v2/Users' \
  -H 'Authorization: Bearer scim_…' \
  -H 'Content-Type: application/scim+json' \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "dana@corp.com",
    "externalId": "okta|1",
    "name": {"givenName": "Dana", "familyName": "Rivera"},
    "emails": [{"value": "dana@corp.com", "primary": true}],
    "active": true
  }'
```

Answers `201` with the created resource. Notes that follow from the mapper
(`Api\Support\ScimMapper`) and `DatabaseDirectorySync`:

- `userName` is **required**; an absent or empty one is `400 invalidValue`.
- `externalId` is the provisioning key. When the body omits it, `userName` is used
  instead. A `POST` whose `externalId` already exists in the directory updates that
  row (`updateOrCreate`) and still answers `201`.
- `emails` is multi-valued on the wire but the platform keeps **one** address: the
  entry marked `"primary": true`, else the first with a value. It is returned as
  `[{value, primary: true}]`.
- `displayName` falls back to `name.formatted`, then to `givenName + familyName`,
  then to `userName`. The name **parts** are persisted, so a later single-part PATCH
  merges instead of erasing the other part.
- `active` defaults to `true` when absent or `null`.
- Provisioning links a local subject, adds organization membership, and emits
  `directory.user.provisioned`.

### Enterprise User extension

`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User` is accepted on create,
PATCH (both the URN-qualified path `urn:…:User:department` and the pathless nested
object) and returned when non-empty, with the URN appended to `schemas`. The stored
set is exactly `employeeNumber`, `costCenter`, `organization`, `division`,
`department`, `manager`; any other key under the URN is dropped on create and is
`400 invalidPath` when patched by an explicit path.

### Read, replace, patch

`PUT` is a full replace and re-provisions from the body:

- `userName` is required (`400 invalidValue` without it).
- The **URL** is the identity. A body `externalId` naming a different resource is
  `400 mutability`; an omitted `externalId` is pinned to the URL-located row rather
  than re-keying the write.

`PATCH` accepts both shapes IdPs send — an explicit `path`, and the pathless
"partial resource in `value`" form:

```bash
curl -sS -X PATCH 'https://id.example.com/scim/v2/Users/01J…' \
  -H 'Authorization: Bearer scim_…' \
  -H 'Content-Type: application/scim+json' \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {"op": "replace", "path": "active", "value": false},
      {"op": "replace", "path": "phoneNumbers[type eq \"mobile\"].value", "value": "+45 12 34 56 78"}
    ]
  }'
```

| Aspect | Behaviour |
| --- | --- |
| `Operations` key | Matched case-insensitively (`operations`, `OPERATIONS`); must be a non-empty array of objects. |
| `op` | Only `add`, `remove`, `replace` (case-insensitive). `add` and `replace` both set the value. |
| Addressable paths | `active`, `userName`, `displayName`, `name` (whole object), `name.formatted`, `name.givenName`, `name.familyName`, `emails`, and the enterprise attributes. |
| Value-filter paths | Stripped: `emails[type eq "work"].value`, `emails[type EQ 'work'].value`, `emails[primary eq true].value` all resolve to `emails`. |
| Tolerated paths | Schema-defined attributes the platform does not store are accepted and ignored: `phoneNumbers`, `addresses`, `photos`, `ims`, `roles`, `groups`, `entitlements`, `x509Certificates`, `title`, `userType`, `nickName`, `profileUrl`, `preferredLanguage`, `locale`, `timezone`, `name.middleName`, `name.honorificPrefix`, `name.honorificSuffix`. A deactivation push that also carries them still deactivates. |
| Unknown paths | Anything else is `400 invalidPath`, and **no** part of the request is applied. |
| `remove` | Clears `displayName`, `name.formatted`, `name.givenName`, `name.familyName`, `emails`. A `remove` with no `path` is `400 noTarget`. `userName`, `externalId` and `active` are not clearable — deactivation is `replace active:false`. |
| Name recomposition | Patching `name.givenName`/`name.familyName` without an explicit `displayName` recomposes the display name from the merged parts. |

`active` is parsed strictly by `Cbox\Id\Scim\Support\ScimBoolean`: the JSON literals
`true`/`false`, and the strings `"true"`/`"false"` in any case and trimmed (Entra
sends `"False"`). Anything else — `"fasle"`, `"no"`, `"1"`, `0`, `1` — is
`400 invalidValue`, because coercing a typo here is a deprovision.

### Delete

```bash
curl -sS -X DELETE 'https://id.example.com/scim/v2/Users/01J…' -H 'Authorization: Bearer scim_…'
# 204 No Content
```

`DELETE` **deprovisions**: the directory row is marked inactive, the local subject is
deactivated, organization membership is removed, and every session that subject holds
is revoked immediately. The `directory_users` row is not physically removed, so a
subsequent `GET /scim/v2/Users/{id}` still resolves and reports `"active": false`.

`DELETE` of an id this directory does not have is **`404`** (RFC 7644 §3.6) — it used
to answer `204`, which told the IdP a deprovision had succeeded for an id the server
never held.

## Groups

```bash
curl -sS -X POST 'https://id.example.com/scim/v2/Groups' \
  -H 'Authorization: Bearer scim_…' \
  -H 'Content-Type: application/scim+json' \
  -d '{"displayName": "Engineering", "externalId": "grp|1",
       "members": [{"value": "01J…alice"}, {"value": "01J…bob"}]}'
```

- `displayName` is required on `POST` and `PUT` (`400 invalidValue` otherwise).
- `members[].value` is the platform's **`DirectoryUser` id** (the SCIM `id`), not the
  `externalId`. Ids that are not users of this directory are silently dropped rather
  than erroring.
- `PUT` replaces membership with exactly the supplied set.
- `PATCH` supports: `add` / `replace` on `path: "members"`; `remove` with
  `members[value eq "<id>"]` (one member) or bare `members` (all); rename via
  `{"op":"replace","path":"displayName","value":"…"}` or the pathless
  `{"op":"replace","value":{"displayName":"…"}}`. A pathless `replace` carrying
  `members` replaces membership; one that carries no `members` leaves membership
  untouched. `path` and `value` keys are matched case-insensitively.
- Group `PATCH` is transactional: a later invalid operation rolls back the earlier
  ones, so a group is never left half-edited.
- Every membership change emits `directory.group.membership_changed`, which
  `AccessControl\Listeners\ReconcileGroupRolesOnDomainEvent` consumes to reconcile
  group→role assignments.
- `DELETE` detaches members and removes the group row; a subsequent read is `404`.

### `members` is omitted from listings

`GET /Groups` **omits** `members` entirely unless the client asks for it. Omitted, not
emitted empty — `"members": []` would assert the group has no members, which is a
different fact. The listing does not even query the membership pivot.

Ask for it with the RFC 7644 §3.9 `attributes` parameter:

```bash
curl -sS 'https://id.example.com/scim/v2/Groups?attributes=members' -H 'Authorization: Bearer scim_…'
# fully-qualified names work too:
curl -sS 'https://id.example.com/scim/v2/Groups?attributes=urn:ietf:params:scim:schemas:core:2.0:Group:members' …
```

Reading a **single** group returns members by default; suppress them with
`?excludedAttributes=members`. `/Schemas` declares `Group.members` with
`"returned": "request"` to match. This is the only attribute selection implemented:
no other attribute can be included or excluded, on either resource.

## Filtering

`/Users` filters are parsed by `Directory\Support\ScimUserFilter` over a closed set of
attributes and a type system (`ScimFilterAttribute`, `ScimValueType`).

| Attribute | Compared as | Column |
| --- | --- | --- |
| `userName` | case-**insensitive** text | `user_name_lower` |
| `emails`, `emails.value` | case-**insensitive** text | `email_lower` |
| `externalId` | case-**sensitive** text (client-assigned, opaque) | `external_id` |
| `active` | boolean | `active` |
| `meta.lastModified` | timestamp | `updated_at` |
| `meta.created` | timestamp | `created_at` |

Attribute names are matched case-insensitively (RFC 7643 §2.1). Any attribute not in
the table — `nickName`, `title`, … — is `400 invalidFilter`.

| Operator | Allowed on | Notes |
| --- | --- | --- |
| `eq`, `ne` | every attribute | |
| `co`, `sw`, `ew` | text attributes only | Translated to `LIKE`; `%` and `_` in the value are escaped, so they match literally. |
| `gt`, `ge`, `lt`, `le` | timestamp attributes only | The delta-sync watermark comparison. |
| `pr` | every attribute | `IS NOT NULL`. |

Clauses combine with a **single** top-level `and` or `or`. Grouping parentheses,
`not`, nested/value-path filters, and mixing `and` with `or` in one expression are all
refused — the parser does not guess precedence.

### Filter values are type-checked

A literal that cannot be a value of the attribute's type refuses the **whole** filter
with `400 invalidFilter`, rather than being coerced and answering with a confidently
wrong result set:

| Filter | Result |
| --- | --- |
| `active eq true` / `active eq "false"` | Parsed. |
| `active eq "fasle"`, `active eq "0"`, `active eq ""` | `400 invalidFilter` |
| `active co "tru"` | `400 invalidFilter` (substring match on a boolean) |
| `userName gt "a"` | `400 invalidFilter` (ordering on text is not implemented) |
| `meta.lastModified gt "2026-07-10T00:00:00Z"` | Parsed. |
| `meta.lastModified gt "yesterday"`, `… gt ""` | `400 invalidFilter` |

Timestamp literals must be xsd:dateTime as RFC 7643 §2.3.5 defines it, and are rebased
onto `config('app.timezone')` — the frame the `created_at`/`updated_at` columns are
stored in — while `meta` is emitted in UTC, so a watermark round-trips correctly on a
non-UTC application timezone.

`/Groups` filtering is far narrower by design: exactly one clause, exactly
`displayName eq "…"` or `externalId eq "…"`, value compared as sent. Anything else is
`400 invalidFilter`.

### Case-insensitive identity on every driver

`userName` and the primary email are stored in dedicated folded columns
(`user_name_lower`, `email_lower`, added by
`2026_07_25_000100_add_normalized_scim_columns_to_directory_users`, maintained by a
`saving` hook on `DirectoryUser` and indexed with `directory_id`). Equality no longer
depends on the database collation, which had made these case-sensitive on PostgreSQL
and case-insensitive on MySQL:

- `userName eq "DANA.RIVERA@CORP.COM"` matches a user stored as `Dana.Rivera@corp.com`
  on every driver;
- and a create whose `userName` differs from an existing one **only in case** now
  collides: `409 uniqueness`, not a second account for one person.

## Discovery

`GET /scim/v2/ServiceProviderConfig` reports the truth, including the gaps:

| Capability | Advertised |
| --- | --- |
| `patch.supported` | `true` |
| `filter.supported` / `filter.maxResults` | `true` / `200` |
| `bulk.supported` | `false` |
| `changePassword.supported` | `false` |
| `sort.supported` | `false` |
| `etag.supported` | `false` |
| `authenticationSchemes[0].type` | `oauthbearertoken` |

`GET /scim/v2/Schemas` returns three schemas — core User, Enterprise User, Group. The
User schema declares `userName` (required, `uniqueness: server`), `externalId`,
`name` (with `formatted`, `givenName`, `familyName`, plus `middleName`,
`honorificPrefix`, `honorificSuffix` marked `returned: never` because they are
accepted and discarded), `displayName`, `emails` (with `value`, `display`, `type`,
`primary`; `display` and `type` are `returned: never`) and `active`. Declaring `name`
and `emails` matters in practice: a schema import that lists only scalars leaves an
admin unable to map email or first/last name at all.

`GET /scim/v2/ResourceTypes` returns `User` (with the Enterprise extension declared
as optional) and `Group`.

## Error semantics

Every failure is an RFC 7644 §3.12 `Error` envelope
(`urn:ietf:params:scim:api:messages:2.0:Error`) with `status` and, where the RFC
defines one, `scimType`:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "400",
  "scimType": "invalidSyntax",
  "detail": "A PATCH request must carry a non-empty \"Operations\" array (RFC 7644 §3.5.2)."
}
```

| Condition | Status | `scimType` |
| --- | --- | --- |
| Missing, unknown or inactive bearer token | `401` | — (plus `WWW-Authenticate: Bearer realm="SCIM"`) |
| Unknown user/group id on `GET`, `PUT`, `PATCH`, `DELETE` (including another environment's id) | `404` | — |
| `POST`/`PUT` `/Users` without `userName` | `400` | `invalidValue` |
| `POST`/`PUT` `/Groups` without `displayName` | `400` | `invalidValue` |
| `active` present but not a SCIM boolean (create, replace, or patch) | `400` | `invalidValue` |
| `Operations` absent, empty, not an array, or containing a non-object | `400` | `invalidSyntax` |
| `op` missing or not `add`/`remove`/`replace` (User **and** Group) | `400` | `invalidSyntax` |
| PATCH `path` the server cannot interpret (User and Group) | `400` | `invalidPath` |
| `remove` with no `path` | `400` | `noTarget` |
| `PUT` body `externalId` naming a different resource | `400` | `mutability` |
| Unparsable or unsupported `filter` (`/Users` or `/Groups`) | `400` | `invalidFilter` |
| `userName` already taken in this directory, including a case variant | `409` | `uniqueness` |
| Email already belongs to a platform account | `409` | `uniqueness` |
| Rate limit exceeded | `429` | — |

Three consequences worth stating plainly, because they are all deliberate reversals of
a silent-success behaviour:

- **A PATCH the server could not read is a `400`, not a `200`.** A body with a
  malformed or absent `Operations` member used to be degraded to "no operations" and
  answered `200` with the unchanged resource, so an IdP recorded a deactivation that
  never happened and never retried it. A merely lower-cased `operations` is legal SCIM
  and is still accepted.
- **A non-boolean `active` is a `400`.** It used to be coerced (`"fasle"` → `false`)
  and answered `200` — a deprovision caused by a typo.
- **`DELETE` of an unknown id is a `404`.** It used to be `204`.

### Rate limiting

The SCIM group is throttled at **120 requests per minute** (`throttle:120,1`). Because
`ScimContentType` sits *outside* the throttle, a `429` is re-framed into the SCIM
`Error` envelope with `status: "429"` and `detail: "Too Many Attempts."`, served as
`application/scim+json`, with the original `Retry-After` header carried across. A
plain Laravel `{"message":"Too Many Attempts."}` in `application/json` is unparsable
to a SCIM client, which reads it as a fatal connector fault instead of "back off".

## Honest scope

What this server does **not** implement:

- **No `/Bulk`** (advertised as `bulk.supported: false`, `maxOperations: 0`).
- **No `/Me`** endpoint, and no `.search` (`POST /.search`) query endpoint — filtering
  is query-string only.
- **No sorting.** `sortBy` / `sortOrder` are ignored; results are always ordered by
  `id`. Advertised as `sort.supported: false`.
- **No ETags / optimistic concurrency.** `meta.version` is not emitted and
  `If-Match` / `If-None-Match` are not honoured. Advertised as `etag.supported: false`.
- **No `changePassword`**; passwords are not part of the mapped profile.
- **Filter gaps:** no grouping parentheses, no `not`, no nested or complex value-path
  filters (`emails[type eq "work"] pr`), no mixing `and` with `or`, no ordering
  comparisons on text, and only the seven `/Users` attributes listed above. `/Groups`
  supports a single `displayName`/`externalId` equality clause only.
- **Attribute selection is limited to `Group.members`.** `attributes` /
  `excludedAttributes` are not honoured for any other attribute or for `/Users`.
- **`DELETE /Users/{id}` is a soft deprovision** — the row remains and reads back as
  `active: false`.
- **Some accepted attributes are discarded**, by design, and `/Schemas` says so with
  `returned: "never"`: `name.middleName`, `name.honorificPrefix`,
  `name.honorificSuffix`, and per-address `emails[].display` / `emails[].type`. The
  wider tolerated set (`phoneNumbers`, `addresses`, `title`, `userType`, …) is accepted
  and ignored rather than refused, so a deprovision push carrying them still applies.
- **Group membership does not accept `externalId` references** — `members[].value` must
  be the SCIM `id` of a user in the same directory; unknown ids are ignored, not
  reported.
- **No group `displayName` uniqueness** is enforced.

## Related

- [Outbound SCIM provisioning](outbound-provisioning.md) — the mirror direction: the
  platform as SCIM client, pushing to a downstream app.
- [Custom SCIM attribute mapping](../extension-points/custom-scim-attribute-mapping.md)
  — per-connection attribute mapping for that outbound direction.
- [Environments & the isolation model](environments.md) — the boundary a directory
  token can never cross.
- [Organization access](organization-access.md) — where the groups this endpoint syncs
  turn into roles.
