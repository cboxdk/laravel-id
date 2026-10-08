---
title: Connect Microsoft Entra ID and Okta over SCIM
weight: 45
description: Register a directory, point Microsoft Entra ID or Okta provisioning at /scim/v2, and know which settings matter on the IdP side
---

# Connect Microsoft Entra ID and Okta over SCIM

This recipe connects a customer's identity provider to the platform's inbound SCIM 2.0
server, so users and groups are provisioned, updated and deprovisioned from the IdP.
See [Inbound SCIM provisioning server](../core-concepts/scim.md) for everything the
server does; this page is the setup and the IdP-side settings.

Both IdPs are covered by replay tests in this package
(`tests/Feature/Api/ScimEntraConformanceTest.php`,
`tests/Feature/Api/ScimOktaConformanceTest.php`): the request bodies are the ones each
vendor documents, verbatim.

## 1. Register a directory and hand out its token

One directory per organization connection. The token is shown once.

```php
use Cbox\Id\Directory\Contracts\Directories;

$registered = app(Directories::class)->register($organization->id, 'Corporate Entra ID');

$registered->token;   // "scim_…" — give it to the IdP admin; it is never shown again
```

The base URL is served on the environment's host (the same host as its issuer), and the
token only ever addresses this one directory.

Check it before configuring anything on the IdP side:

```bash
curl -sS "$BASE/ServiceProviderConfig" -H "Authorization: Bearer $TOKEN"
```

The response advertises `patch`, `filter` (`maxResults: 200`), `sort`, `etag` and
`bulk` (with its limits) as supported, and `changePassword` as not.

## 2. Microsoft Entra ID

In the Entra admin center, on the enterprise application: **Provisioning** →
provisioning mode **Automatic**.

| Setting | Value |
| --- | --- |
| Tenant URL | `https://<environment host>/scim/v2` |
| Secret Token | the `scim_…` token |

**Test Connection** reads a user and a group with a filter; both must answer `200`
(an empty `ListResponse` is fine).

### Mappings

- **Matching attribute for users:** `userName` (the default) or `externalId`. Both
  are filterable with `eq`. If you key uniqueness on the work email instead, Entra
  queries `emails[type eq "work"].value eq "…"` — that works too.
- **Matching attribute for groups:** `displayName`. Group display names are unique per
  directory (any case); a duplicate create is `409 uniqueness`, which is what Entra
  expects.
- **Attributes the platform stores:** `userName`, `externalId`, `active`,
  `displayName`, `name.givenName`, `name.familyName`, `name.formatted`, the work email,
  and the Enterprise User attributes (`employeeNumber`, `costCenter`, `organization`,
  `division`, `department`, `manager`). Entra's default mapping also sends phone numbers,
  addresses, `title` and others — those are accepted and ignored, never refused, so a
  deprovision carrying them still deactivates the user.
- **Do not map `externalId` to something that changes.** It is the provisioning key and
  is immutable once provisioned; a PATCH that changes it is `400 mutability`.

### The compliance flag

Entra's PATCH requests come in two shapes, depending on whether the tenant URL carries
Microsoft's `?aadOptscim062020` flag. The platform accepts **both**, so the flag is
optional:

| Request | Without the flag | With the flag |
| --- | --- | --- |
| Deactivate | `{"op":"Replace","path":"active","value":"False"}` | `{"op":"replace","path":"active","value":false}` |
| Several attributes | one `Replace` per path | one pathless `replace` with `name.givenName`, URN-qualified keys, … |
| Remove a member | `{"op":"Remove","path":"members","value":[{"value":"<id>"}]}` | `{"op":"remove","path":"members[value eq \"<id>\"]"}` |

### Deprovisioning

Entra deprovisions with `active: false` (and, depending on the app's settings, a
`DELETE`). Both revoke every session of the person immediately. A `DELETE` here is a
soft deprovision: the user still reads back, with `active: false`, and Entra can
re-activate it later with a PATCH.

## 3. Okta

In the Okta admin console, on the app integration's **Provisioning** tab, enable SCIM
provisioning and configure the integration:

| Setting | Value |
| --- | --- |
| SCIM connector base URL | `https://<environment host>/scim/v2` |
| Unique identifier field for users | `userName` |
| Supported provisioning actions | Import New Users and Profile Updates, Push New Users, Push Profile Updates, Push Groups (as needed) |
| Authentication Mode | HTTP Header — the `scim_…` token as the Bearer token |

**Test Connector Configuration** reads `GET /Users?startIndex=1&count=2` (and
`GET /Groups?startIndex=1&count=100` when group import is on).

What Okta then sends, and the platform answers:

- **Existence check** — `GET /Users?filter=userName eq "…"&startIndex=1&count=100`.
  `userName` is matched case-insensitively; no match is `200` with `totalResults: 0`.
- **Create** — `POST /Users` with `password`, `locale` and an empty `groups`: the
  password is ignored (not part of the profile). Creating a user that already exists
  is `409 uniqueness`.
- **Profile update** — a `GET` followed by a full `PUT` of the resource (or a PATCH).
- **Deactivate / reactivate** — `PATCH` with `{"op":"replace","value":{"active":false}}`.
  Okta never sends `DELETE` for users.
- **Push Groups** — create, a pathless rename (`{"id": …, "displayName": …}`), membership
  as `remove` with `members[value eq "<id>"]` plus `add` on `members`, or a `replace` of
  `members`, and `DELETE` when a pushed group is unlinked with delete.
- **Paging** — `startIndex` advanced while `totalResults` exceeds what was read. The
  order is stable across requests (by `id`, or by `sortBy` with `id` breaking ties).

## 4. What neither IdP uses — but you can

Microsoft Entra ID and Okta both provision with filters and PATCH, one request per
change. The platform also implements, for other clients and your own tooling:

- **`/Bulk`** — many operations, with `bulkId` cross-references, in one request
  (`cbox-id.scim.bulk.max_operations`, `…max_payload_size`).
- **ETags** — `meta.version` / `ETag` on every resource, `If-Match` → `412`,
  `If-None-Match` → `304`.
- **Sorting** — `sortBy` / `sortOrder` on `/Users` and `/Groups`.
- **The full filter grammar** — `not`, grouping, value paths, URN-qualified paths.

## Troubleshooting

| Symptom at the IdP | Cause | Fix |
| --- | --- | --- |
| `401` on Test Connection | Wrong or revoked token, or the URL points at another environment's host. | Use the token issued for this directory, on its environment's host. |
| `409 uniqueness` on create | The user already exists in the directory (same `externalId`, or a `userName` differing only in case), or the email belongs to another account on the platform. | Let the IdP match the existing user (its existence check), or resolve the duplicate account. |
| `409 uniqueness` on a group | Another group has that `displayName` (any case). | Rename one of them at the IdP. |
| `400 invalidFilter` | A filter on an attribute the platform does not store (`title`, `phoneNumbers`, …). | Change the matching attribute to one the platform stores. |
| `400 mutability` | A PATCH or PUT changing `externalId`. | Map `externalId` to an immutable source attribute. |
| `429` | The SCIM surface is rate-limited (`throttle:120,1`). | Nothing — both IdPs back off and retry on the `Retry-After`. |
