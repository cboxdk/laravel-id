---
title: Shared user preferences and metadata
description: Share versioned user settings between explicitly authorized groups of applications.
weight: 35
---

# Shared user preferences and metadata

User properties belong to a user **within one environment**. Each namespace holds an independent JSON object and version. The reserved `preferences` namespace has a Cbox-defined schema; other namespaces accept application-defined JSON. Sharing is explicit: a namespace can grant access to two apps, ten apps, or one app. A token scope by itself grants no namespace access.

## Grant a group of apps access

Resolve `Cbox\Id\UserProperties\Contracts\PropertyNamespaces` from trusted host code:

```php
$namespaces->configure(
    'preferences',
    readers: [$calendarClientId, $tasksClientId],
    writers: [$calendarClientId, $tasksClientId],
    webhooks: [$calendarEndpointId => $calendarClientId, $tasksEndpointId => $tasksClientId],
);
$namespaces->configure('planning', readers: [$calendarClientId], writers: [$calendarClientId]);
```

These are OAuth **client ids**, not database row ids. Writers must also be readers. Clients and webhook endpoints must belong to the current environment and be environment-wide (no organization owner). A host must only expose this control-plane capability to administrators. Calling `configure` replaces the complete grant set. Empty lists revoke access; documents and their versions remain intact. Grants are checked live, including just before a queued webhook is sent. There is no wildcard grant or implicit owner access.

The Cbox ID application provides authenticated management actions for this registry. Those actions are an app capability, not a library route.

## Read and patch from an app

Register `user_properties:read` and/or `user_properties:write` on the OAuth client and request the needed scopes when acquiring an access token. The token must be for the issuer, not another API. A user token can only address its own user. An explicitly granted environment-wide app can use client credentials to synchronize users in that environment. DPoP-bound tokens also require their proof.

```http
GET /oauth/users/USER_ID/properties/preferences
Authorization: Bearer ACCESS_TOKEN
```

An unwritten document responds with `data: {}` and `version: 0`:

```json
{"user_id":"USER_ID","namespace":"preferences","data":{},"version":0}
```

```http
PATCH /oauth/users/USER_ID/properties/preferences
Authorization: Bearer ACCESS_TOKEN
Content-Type: application/json

{"version":0,"set":{"theme":"dark","language":"en","locale":"da-DK","timezone":"Europe/Copenhagen"},"remove":[]}
```

The response is the new snapshot, with version `1`. Every patch supplies the version read previously. A stale version returns **409**: fetch again, reconcile the user's intended change, and retry. An unchanged patch keeps its version and emits no event. A namespace lock serializes writes, including the first document creation and grant changes.

Patches operate on **top-level keys**. Setting `layout` replaces the entire value of `layout`; dots in keys are literal, not JSON paths. Unmentioned keys survive. `remove` explicitly deletes keys; JSON `null` is an ordinary custom value. A key cannot appear in both `set` and `remove`. Nested objects (including `{}`) and arrays stay distinct.

Custom key names start with a letter and contain at most 128 ASCII letters, digits, dots, underscores or hyphens. Documents allow at most 100 keys, 16 KiB of encoded JSON and 16 levels of JSON nesting. HTTP bodies are bounded to 32 KiB. The package validates these bounds, not the app-specific meaning of custom values. Apps sharing a namespace own that contract. Values never enter tokens, authorization claims, or change-event payloads.

## Built-in preferences

| Key | Value |
| --- | --- |
| `language` | Language tag for the interface, e.g. `en` or `da` |
| `locale` | Regional formatting tag, e.g. `da-DK`, independent of interface language |
| `timezone` | IANA time zone, e.g. `Europe/Copenhagen` |
| `date_format` | `locale`, `yyyy-MM-dd`, `dd/MM/yyyy`, `MM/dd/yyyy`, `dd.MM.yyyy` |
| `time_format` | `locale`, `12h`, `24h` |
| `week_start` | Integer 1–7, Monday–Sunday |
| `theme` | `system`, `light`, `dark` |

Unknown preference keys and null preference values are rejected. Remove a preference to return to app/device defaults. Missing theme means the app should follow the system; missing date/time formats follow the chosen locale. Format identifiers are shared tokens, **not** PHP or JavaScript format strings: consumers map them to their formatter. This API stores preferences; each consuming app applies them to its own UI and local cache. Cbox ID's hosted language cookie is not automatically replaced by this API.

## Receive changes

Subscribe an endpoint to `user.preferences.updated` and/or `user.metadata.updated`, then grant that endpoint access in each relevant namespace. `*` subscriptions still require explicit namespace access. An endpoint is mapped to one reader app per namespace. Unrelated and organization-owned endpoints receive nothing for these events.

The ordinary signed webhook envelope contains this `data`:

```json
{
  "event_id": "01EVENT",
  "user_id": "USER_ID",
  "namespace": "preferences",
  "changed_keys": ["theme"],
  "version": 2,
  "client_id": "APP_CLIENT_ID",
  "occurred_at": "2026-11-04T12:00:00+00:00"
}
```

The document and its event commit atomically through the transactional outbox. A queue job wakes the relay after commit; the scheduled relay recovers if that job is lost. Configure an asynchronous queue and run its workers and the scheduler. Delivery latency depends on queue and relay backlog; it is not a synchronous broadcast guarantee. The wake-up job uses the webhook queue configuration and drains a bounded batch of pending domain events.

Receivers verify the webhook signature, deduplicate by `event_id`, and ignore versions at or below the cached version. Fetch the current document using the receiving app's credentials, then apply the returned version only if it is newer than the local copy. An event may arrive late or out of order, and several events may collapse into one fetch. Reconcile caches on login or periodic refresh as well, especially after grants are restored: revocation does not replay historical events. Push the refreshed settings to open browser sessions through the consuming app's realtime transport.

User erasure removes all namespace documents through the existing erasure pipeline. Pending property notifications for an inactive or erased user are refused. Ordinary `user.erased` handling remains responsible for removing copies in consuming apps.

## Host code and tests

Resolve `UserProperties` to call `read($clientId, $userId, $namespace)` or `patch(..., new PropertyPatch($version, (object) $values, $removedKeys))`. These calls enforce namespace grants and active subjects. The HTTP adapter additionally enforces token scopes, audience, DPoP, and user ownership. Host code is responsible for authenticating the caller before choosing a client id.

`InteractsWithUserProperties::makePropertyNamespace()` exercises the real namespace contract in tests. The interface bindings can be replaced by a host; webhook delivery is narrowed through `WebhookDeliveryPolicy`. A replacement policy must retain the namespace boundary.
