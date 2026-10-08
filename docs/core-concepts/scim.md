---
title: Inbound SCIM provisioning server
description: The SCIM 2.0 server at /scim/v2 — directory-scoped bearer auth, the full User and Group lifecycle, the RFC 7644 filter grammar, sorting, ETags, /Bulk, and RFC 7644 error semantics
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
| `GET` | `/scim/v2/Users` | List, with `filter`, `sortBy`, `sortOrder`, `startIndex`, `count`. |
| `POST` | `/scim/v2/Users` | Create (provision). |
| `GET` | `/scim/v2/Users/{id}` | Read one (`If-None-Match` → `304`). |
| `PUT` | `/scim/v2/Users/{id}` | Full replace (`If-Match` → `412`). |
| `PATCH` | `/scim/v2/Users/{id}` | Partial update (path and pathless forms; `If-Match`). |
| `DELETE` | `/scim/v2/Users/{id}` | Deprovision (`If-Match`). |
| `GET` | `/scim/v2/Groups` | List, with `filter`, `sortBy`, `sortOrder`, `startIndex`, `count`, `attributes`. |
| `POST` | `/scim/v2/Groups` | Create. |
| `GET` | `/scim/v2/Groups/{id}` | Read one (members included by default). |
| `PUT` | `/scim/v2/Groups/{id}` | Full replace, including membership. |
| `PATCH` | `/scim/v2/Groups/{id}` | Rename and membership add/remove/replace. |
| `DELETE` | `/scim/v2/Groups/{id}` | Delete. |
| `POST` | `/scim/v2/Bulk` | Many of the operations above in one request (RFC 7644 §3.7). |

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
        "location": "https://id.example.com/scim/v2/Users/01J…",
        "version": "W/\"3f6c0e9b2a7d41c58e10\""
      }
    }
  ]
}
```

- `startIndex` is 1-based and defaults to 1; `count` defaults to and is capped at
  **200** (`DatabaseDirectoryUsers::MAX_PAGE`); `count=0` answers the total with no
  resources. Results are ordered by `id` unless `sortBy` says otherwise (see
  [Sorting](#sorting)).
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
  instead. A `POST` whose `externalId` already exists in the directory is
  `409 uniqueness` (RFC 7644 §3.3) — it used to update that row and answer `201`,
  telling the IdP it had created a resource it had not. Both the Microsoft Entra ID
  validator and Okta's SCIM test suite POST the same user twice and require the 409.
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
`400 invalidPath` when patched by an explicit path. Attribute names under the URN are
matched in any case. An unqualified name only the extension defines (`manager`,
`department`) is read as the extension's — Entra patches `"path": "manager"`.

`manager` is always stored and returned as the complex attribute RFC 7643 §4.3
defines — `{value, $ref, displayName}` — whether it arrived as that object, as a bare
id string, or (from Entra) as a one-element list of `{$ref, value}`. Its
sub-attributes are addressable: `urn:…:User:manager.displayName`.

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
| `op` | Only `add`, `remove`, `replace`, in any case (Entra sends `Add`/`Replace`/`Remove`). `add` and `replace` both set the value. |
| Path grammar | Parsed as RFC 7644 §3.5.2 defines it — `attrPath / valuePath [subAttr]` — by `Cbox\Id\Scim\Filter\ScimFilterParser`. Fully-qualified paths work for the core schema (`urn:ietf:params:scim:schemas:core:2.0:User:name.familyName`) and the Enterprise extension. |
| Addressable paths | `active`, `userName`, `displayName`, `name` (whole object), `name.formatted`, `name.givenName`, `name.familyName`, `emails`, `externalId` (see below), and the enterprise attributes. |
| Value filters | **Evaluated**, not stripped. The one stored address is modelled as `{type: "work", primary: true, value: <address>}`, so `emails[type eq "work"].value`, `emails[type EQ "work"].value`, `emails[primary eq true].value` and `emails[type eq "work" and primary eq true].value` write it, and `emails[type eq "home"].value` — a secondary address this server does not model — is accepted and left alone rather than overwriting somebody's sign-in address. A filter the grammar cannot read on `emails` (or on a tolerated multi-valued attribute) is treated the same way; on anything else it is `400 invalidPath`. Single-quoted values (`emails[type eq 'work']`) are accepted in paths. |
| Tolerated paths | Schema-defined attributes the platform does not store are accepted and ignored: `phoneNumbers`, `addresses`, `photos`, `ims`, `roles`, `groups`, `entitlements`, `x509Certificates` (with any value filter or sub-attribute, e.g. `addresses[type eq "work"].streetAddress`), `title`, `userType`, `nickName`, `profileUrl`, `preferredLanguage`, `locale`, `timezone`, `name.middleName`, `name.honorificPrefix`, `name.honorificSuffix`. A deactivation push that also carries them still deactivates. |
| `externalId` | The provisioning key, so immutable once provisioned: replacing it with its current value is accepted, with anything else is `400 mutability` (the same rule `PUT` applies). |
| Pathless `value` | Every key is read as a path, so `{"name.givenName": "…", "urn:…:enterprise:2.0:User:employeeNumber": "…"}` (Entra's compliance-flag shape) and `{"active": false}` (Okta's deactivation) both land. Keys that are not attributes — `id`, `meta`, `schemas` — are ignored. |
| Unknown paths | Anything else is `400 invalidPath`, and **no** part of the request is applied. |
| `remove` | Clears `displayName`, `name.formatted`, `name.givenName`, `name.familyName`, `name` (both parts), `emails` (or the address a filter selects), and enterprise attributes and `manager` sub-attributes. A `remove` with no `path` is `400 noTarget`. `userName`, `externalId` and `active` are not clearable — deactivation is `replace active:false`. |
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

- `displayName` is required on `POST` and `PUT` (`400 invalidValue` otherwise) and
  unique per directory, compared without regard to case: a create, replace or rename
  onto a name another group has is `409 uniqueness`. (The table has always carried a
  unique index; a duplicate used to surface as a `500`.) Entra matches groups on
  `displayName`, and its validator requires the 409.
- `members[].value` is the platform's **`DirectoryUser` id** (the SCIM `id`), not the
  `externalId`. Ids that are not users of this directory are silently dropped rather
  than erroring.
- `PUT` replaces membership with exactly the supplied set.
- `PATCH` supports: `add` (attach) and `replace` (set exactly — Okta's shape) on
  `path: "members"`; `remove` on bare `members` with a `value` list (Entra's
  `{"op":"Remove","path":"members","value":[{"value":"<id>"}]}`) or with no value (all);
  `remove` with any value filter — `members[value eq "<id>"]`,
  `members[value eq "a" or value eq "b"]`, `members[display eq "…"]` — which detaches
  exactly the members it selects (evaluated in SQL, so a large group is not loaded);
  rename via `add` or `replace` on `displayName` (also URN-qualified) or the pathless
  `{"op":"replace","value":{"displayName":"…"}}` (Okta adds the `id`, which is ignored);
  and `externalId` set or removed. A pathless `replace` carrying `members` replaces
  membership; one that carries no `members` leaves membership untouched. `add`/`replace`
  on a filtered `members` path, and any member sub-attribute path, are `400 invalidPath`.
  `path` and `value` keys are matched case-insensitively.
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

Filters are parsed by `Cbox\Id\Scim\Filter\ScimFilterParser` — the RFC 7644 §3.4.2.2
grammar (Figure 1), into a typed tree — and translated to SQL by
`Directory\Support\ScimDirectoryQuery` over the attributes the store actually holds
(`Directory\Support\ScimQueryAttributes`).

```bash
# precedence: not > and > or, parentheses to override
filter=userType ne "Employee" and not (emails co "example.com" or emails.value co "example.org")
# value filters: the conditions hold for ONE value of the attribute
filter=emails[type eq "work" and value co "@corp.com"]
filter=members[value eq "01J…"]
# URN-qualified paths, for the core schema and the Enterprise extension
filter=urn:ietf:params:scim:schemas:core:2.0:User:userName sw "J"
filter=urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "Sales"
```

The grammar, in full: every operator (`eq ne co sw ew gt ge lt le pr`), `and`, `or`,
`not (…)`, grouping parentheses, value paths `attr[…]`, attribute paths with one
sub-attribute (`name.familyName`) and an optional schema URN, and JSON values — strings
with JSON escapes (`"O\u0027Malley"`), numbers, `true`, `false`, `null`. Operators,
keywords and attribute names are case-insensitive. One extension: Microsoft Entra ID
documents `emails[type eq "work"].value eq "x"` for user uniqueness keyed on the work
email, and it is read as `emails[type eq "work" and value eq "x"]`.

### Filterable attributes

| `/Users` attribute | Compared as | Stored in |
| --- | --- | --- |
| `id`, `externalId` | case-sensitive text | `id`, `external_id` |
| `userName` | case-insensitive text | `user_name_lower` |
| `active` | boolean | `active` |
| `displayName`, `name.formatted`, `name.givenName`, `name.familyName` | case-insensitive text | the `resource` JSON |
| `emails`, `emails.value` | case-insensitive text | `email_lower` |
| `emails.type`, `emails.primary` | the stored address is the `work`, `primary` one | presence of `email_lower` |
| `meta.created`, `meta.lastModified` | DateTime | `created_at`, `updated_at` |
| Enterprise `employeeNumber`, `costCenter`, `organization`, `division`, `department` | case-insensitive text | the `resource` JSON |
| Enterprise `manager` / `manager.value`, `manager.displayName` | case-sensitive / case-insensitive text | the `resource` JSON |

| `/Groups` attribute | Compared as |
| --- | --- |
| `id`, `externalId` | case-sensitive text |
| `displayName` | case-insensitive text |
| `members` / `members.value`, `members.display`, `members.type` | via the membership — `members[value eq "x"]` is one `EXISTS` |
| `meta.created`, `meta.lastModified` | DateTime |

Anything else — `title`, `phoneNumbers`, an unknown URN — is `400 invalidFilter`.
An attribute that is accepted on write and discarded is never answered as though every
user, or none, had a value.

### Semantics

| Operator | Allowed on | Notes |
| --- | --- | --- |
| `eq`, `ne` | every attribute | `eq null` is "not present", `ne null` is "present". |
| `co`, `sw`, `ew` | text | `LIKE … ESCAPE '!'`; `%`, `_` and `!` in the value match literally on every engine. |
| `gt`, `ge`, `lt`, `le` | text (lexicographic) and DateTime (chronological) | On a boolean: `400 invalidFilter`, as §3.4.2.2 requires. |
| `pr` | every attribute | Present and non-empty. |

- **Two-valued logic.** An absent attribute matches no comparison except `ne`, so
  `not (department eq "Sales")` includes users with no department — SQL's `NULL`
  semantics would silently drop them.
- **Literals are type-checked.** `active eq "fasle"`, `meta.lastModified gt "yesterday"`
  and `active co "tru"` are `400 invalidFilter`, never coerced. DateTime literals must be
  xsd:dateTime (RFC 7643 §2.3.5) and are compared as instants, so an offset
  (`+02:00`) means what it says.
- **Bounded.** A filter longer than 4096 characters, nested deeper than 16 levels or
  carrying more than 64 comparisons is refused before any query runs.
- The parse error names the position where it gave up; an unknown attribute or operator
  is named in the `detail`.
- Every `filter` is nested inside the directory scope, so an `or` can never reach
  another directory's rows.

### Sorting

`sortBy` and `sortOrder` (RFC 7644 §3.4.2.3) work on `/Users` and `/Groups`, over
every single-valued attribute in the tables above (`members`, `emails.type` and
`emails.primary` are not sortable):

```bash
curl -sS 'https://id.example.com/scim/v2/Users?sortBy=name.familyName&sortOrder=descending&count=50' \
  -H 'Authorization: Bearer scim_…'
```

- `sortOrder` defaults to `ascending` and is matched in any case.
- Case-insensitive attributes sort case-insensitively.
- Resources with no value sort last when ascending and first when descending.
- `id` breaks every tie, so paging through a sorted listing is stable.
- An attribute that cannot be sorted on, or a `sortOrder` that is neither value, is
  `400 invalidValue`. The RFC says the server SHALL sort by the attribute; ordering by
  something else would hand a paging client an order it did not ask for.

A host that rebinds `DirectoryUsers` / `DirectoryGroups` keeps working: sorting is the
optional `DirectoryUserSearch` / `DirectoryGroupSearch` capability, and a store
without it answers a `sortBy` with `400 invalidValue` rather than ignoring it.

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

## Versioning with ETags

Every User and Group carries a weak entity-tag (RFC 7644 §3.14) in `meta.version`, and
every single-resource response — including a `201` — carries it as the `ETag` header.

- The tag is derived from the resource id and a revision counter (`version` column,
  added by `2026_10_20_000200_add_version_to_directory_resources`). The counter moves on
  every save that changes the row, so two writes in the same second yield two tags; a
  group's moves when only its membership changes. A write that changes nothing keeps
  the tag.
- `If-Match` on `PUT`, `PATCH` and `DELETE`: a list of tags or `*`. When none matches,
  the answer is `412` with a SCIM Error and nothing is written.
- `If-None-Match` on `GET /Users/{id}` and `GET /Groups/{id}`: when a tag matches, the
  answer is `304 Not Modified` with an empty body and the `ETag` header.
- Tags are compared **weakly** on both headers. RFC 7232 asks for strong comparison on
  `If-Match`, under which a weak tag never matches — but RFC 7644 §3.14 pairs exactly
  these headers with weak tags, so the SCIM reading wins.
- An unknown id is `404` before any precondition is evaluated.
- The counter is not a lock: it makes a lost update detectable for a client that sends
  `If-Match`, the way RFC 7644 intends.

```bash
curl -sS -X PATCH 'https://id.example.com/scim/v2/Users/01J…' \
  -H 'Authorization: Bearer scim_…' -H 'If-Match: W/"3f6c0e9b2a7d41c58e10"' \
  -H 'Content-Type: application/scim+json' \
  -d '{"Operations":[{"op":"replace","path":"displayName","value":"Dana R."}]}'
# 412 if the user changed since that tag was read
```

## Bulk

`POST /scim/v2/Bulk` (RFC 7644 §3.7) runs many operations in one request. Each
operation goes through exactly the code the single-resource endpoint runs
(`Api\Contracts\ScimUserResources` / `ScimGroupResources`), under the same token and
directory scope.

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
  "failOnErrors": 1,
  "Operations": [
    {"method": "POST", "path": "/Users", "bulkId": "qwerty",
     "data": {"userName": "alice@corp.com"}},
    {"method": "POST", "path": "/Groups", "bulkId": "ytrewq",
     "data": {"displayName": "Tour Guides", "members": [{"value": "bulkId:qwerty"}]}},
    {"method": "PATCH", "path": "/Users/01J…", "version": "W/\"3f6c0e9b2a7d41c58e10\"",
     "data": {"Operations": [{"op": "replace", "path": "active", "value": false}]}},
    {"method": "DELETE", "path": "/Users/01J…"}
  ]
}
```

The `BulkResponse` lists each processed operation in request order with `method`,
`bulkId` (when given), `location` (except for a failed `POST`), `version` (on success,
except `DELETE`), `status` as a string, and — for a failure — `response`, the SCIM
Error the single-resource request would have answered.

- **Operations are independent.** "The service provider MUST continue performing as
  many changes as possible and disregard partial failures": there is no transaction
  around the request. `failOnErrors: N` stops after the N-th failure; the response
  then lists only what was processed. It must be a positive integer.
- **`bulkId` references.** Any string that is exactly `bulkId:<id>` — in a `path`
  (`/Users/bulkId:qwerty`) or anywhere in `data` (a group's `members[].value`, the
  Enterprise `manager.value`) — is replaced with the created resource's id. A
  reference to a `POST` later in the request runs that `POST` first. A reference that
  cannot be resolved — no such `bulkId`, its `POST` failed, or a cycle — fails that
  operation with `409 invalidValue`.
- **`version`** is that operation's `If-Match`.
- **Validation per operation.** An unknown `method`, a `path` that is not
  `/Users[/{id}]` or `/Groups[/{id}]`, a `POST` to a resource or without `bulkId`, a
  `PUT`/`PATCH` without `data`, or a `bulkId` used twice fails that operation with
  `400 invalidSyntax`; the rest proceed. A `PATCH`'s `data` may be a PatchOp message
  or a bare list of operations.
- **Limits** (`cbox-id.scim.bulk.*`, advertised in ServiceProviderConfig):
  `max_operations` (default 1000, `CBOX_ID_SCIM_BULK_MAX_OPERATIONS`) and
  `max_payload_size` in bytes (default 1 MiB, `CBOX_ID_SCIM_BULK_MAX_PAYLOAD_SIZE`).
  Exceeding either is a `413` whose detail names the limit; the payload size is checked
  on the raw body before it is decoded.
- A bulk request counts **once** against the SCIM rate limit, however many operations
  it carries — the limits above are what bound its cost.

## Discovery

`GET /scim/v2/ServiceProviderConfig` reports the truth, including the gaps. The bulk
limits are read from the same processor that enforces them:

| Capability | Advertised |
| --- | --- |
| `patch.supported` | `true` |
| `filter.supported` / `filter.maxResults` | `true` / `200` |
| `bulk.supported` / `maxOperations` / `maxPayloadSize` | `true` / `cbox-id.scim.bulk.max_operations` / `…max_payload_size` |
| `changePassword.supported` | `false` |
| `sort.supported` | `true` |
| `etag.supported` | `true` |
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
| `PUT` body `externalId` naming a different resource, or a PATCH changing `externalId` | `400` | `mutability` |
| Unparsable `filter`, or one naming an attribute the store does not hold | `400` | `invalidFilter` |
| `sortBy` on an attribute that cannot be sorted, or an unknown `sortOrder` | `400` | `invalidValue` |
| `POST /Users` with an `externalId` the directory already has | `409` | `uniqueness` |
| `userName` already taken in this directory, including a case variant | `409` | `uniqueness` |
| Email already belongs to a platform account | `409` | `uniqueness` |
| Group `displayName` already used in this directory (any case) | `409` | `uniqueness` |
| `If-Match` that matches no current tag | `412` | — |
| Bulk request over `maxOperations` or `maxPayloadSize` | `413` | — |
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

- **No `/Me`** endpoint, and no `.search` (`POST /.search`) query endpoint — filtering
  is query-string only.
- **No `changePassword`**; passwords are not part of the mapped profile (Okta's
  `password` on create is accepted and ignored).
- **Attribute selection is limited to `Group.members`.** `attributes` /
  `excludedAttributes` are not honoured for any other attribute or for `/Users`.
- **`DELETE /Users/{id}` is a soft deprovision** — the row remains and reads back as
  `active: false`. A later `POST` of the same `externalId` is therefore a `409`; the
  IdP finds the user with a filter and re-activates it with a PATCH.
- **One email per user.** `emails` is multi-valued on the wire; the platform stores the
  primary (work) address. Filters and PATCH value filters treat it as
  `{type: "work", primary: true}`; other addresses are accepted and not kept.
- **Some accepted attributes are discarded**, by design, and `/Schemas` says so with
  `returned: "never"`: `name.middleName`, `name.honorificPrefix`,
  `name.honorificSuffix`, and per-address `emails[].display` / `emails[].type`. The
  wider tolerated set (`phoneNumbers`, `addresses`, `title`, `userType`, …) is accepted
  and ignored rather than refused, so a deprovision push carrying them still applies —
  and is not filterable or sortable.
- **Group membership does not accept `externalId` references** — `members[].value` must
  be the SCIM `id` of a user in the same directory; unknown ids are ignored, not
  reported.
- **A group's ETag does not move when a member's `userName` changes**, although the
  member's `display` in the group representation does (a weak tag; membership itself
  always moves it).
- **Bulk has no circular-reference resolution beyond detection**: RFC 7644 §3.7.1
  allows a `409` after a failed attempt, and that is what a cycle gets.
- Ordering comparisons on text (`userName gt "m"`) and sorting by a JSON-stored
  attribute follow the database's ordering of lower-cased strings, which for
  non-ASCII text can differ between engines.

## Related

- [Outbound SCIM provisioning](outbound-provisioning.md) — the mirror direction: the
  platform as SCIM client, pushing to a downstream app.
- [Custom SCIM attribute mapping](../extension-points/custom-scim-attribute-mapping.md)
  — per-connection attribute mapping for that outbound direction.
- [Environments & the isolation model](environments.md) — the boundary a directory
  token can never cross.
- [Organization access](organization-access.md) — where the groups this endpoint syncs
  turn into roles.
