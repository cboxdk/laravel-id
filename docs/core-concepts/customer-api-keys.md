---
title: Customer API keys
description: Keys your app's end-customers mint for YOUR API — bound to one app, capped at the holder's current permissions, verified by the app with its own client credentials
weight: 11
---

# Customer API keys

An app built on Cbox ID usually has an API of its own, and its customers want keys for
it: a tax platform's customer wants a key their accounting system can call the tax API
with. Customer API keys are that credential.

A key is bound to three things and carries a fourth:

| | |
|---|---|
| **App** | the `client_id` it was issued for. Only that app can verify it. |
| **Organization** | the customer organization it acts in. |
| **Holder** | the user it belongs to. It never outlives their access. |
| **Permissions** | a subset of the app's permissions — a ceiling, never a grant of its own. |

It is the same credential as a user API token (`cbid_pat_…`, see
[Organization access](organization-access.md#user-api-tokens)) — same table, same
SHA-256-at-rest discipline, same tenancy and revocation — bound to one app, and carrying
that app's permissions instead of a coarse verb.

## The two caps

A key can only carry permissions its holder holds **for that app**, and only while they
still hold them.

1. **At issuance.** Every requested permission must be among the holder's effective
   permissions for the app — the same set an access token for that app would carry
   (`AccessChecker::forToken()`: org-wide roles plus the app's own declared roles, never
   another app's). Anything else is refused with `ApiKeyRefusal::PermissionNotHeld`.
2. **At every verification.** The key's permissions are intersected with what the holder
   holds for the app *at that moment*. Demote the holder and the key loses the permission
   on the next request. Grant them more and the key does **not** widen — it only ever
   carries what it was issued with.

Verification also requires, every time:

- the key is not revoked and not past its expiry;
- the holder is an **active** member of the organization, and the membership is not newer
  than the key. Removing a member kills their keys; adding them back later does not bring
  the old keys back.
- the organization is not suspended or archived;
- the holder's account is active.

## Enabling keys for an app

An app opts in by declaring its **key prefix**:

```php
use Cbox\Id\Organization\Contracts\CustomerApiKeys;
use Cbox\Id\Organization\ValueObjects\ApiKeyPrefix;

app(CustomerApiKeys::class)->setPrefix($client->client_id, ApiKeyPrefix::of('ctx_live'));
```

The prefix must match `^[a-z][a-z0-9]{1,15}_(live|test)$`: a lowercase root of 2 to 16
characters, then `live` or `test`. Keys look like `ctx_live_` followed by 48 random
base62 characters. The root `cbid` is reserved for the platform's own credentials, and a
prefix is unique within an environment, so a key found in a log names exactly one app.

`live`/`test` is a label for people and secret scanners. What actually separates a
staging key from a production one is the **environment**: a key verifies only in the
environment it was issued in. Use `_test` on the clients of your non-production
environments.

Clearing the prefix (`setPrefix($clientId, null)`) stops new keys only. Keys already
issued keep verifying until they are revoked.

## Issuing, listing, revoking

```php
use Cbox\Id\Organization\ValueObjects\ApiKeyActor;
use Cbox\Id\Organization\ValueObjects\NewCustomerApiKey;

$issued = app(CustomerApiKeys::class)->issue(new NewCustomerApiKey(
    organizationId: $org->id,
    userId: $user->id,
    clientId: $client->client_id,
    permissions: ['returns:read', 'returns:file'],
    name: 'Accounting sync',          // optional
    expiresAt: now()->addYear(),      // optional; null = no expiry of its own
));

$issued->plaintext;   // show this ONCE — only its hash is stored
$issued->key->prefix; // "ctx_live_Ab3d", a non-secret fragment for listings

$keys->forUser($org->id, $user->id, $client->client_id); // newest first
$keys->forOrganization($org->id);                          // every key in the org
$keys->revoke($keyId, ApiKeyActor::user($admin->id));      // idempotent, returns bool
```

`issue()` throws `CustomerApiKeyRefused`; its `reason` (an `ApiKeyRefusal`) says why:
`unknown_client`, `keys_not_enabled`, `not_a_member`, `organization_inactive`,
`holder_inactive`, `permission_not_held`, `expiry_in_past` or `invalid_input`. Issuing
is a management action, so the reason is reported. Verification never reports one.

**Authorization is yours.** The service does not decide who may issue a key for whom, or
who may revoke which key. Whether a member may mint keys, and whether an admin may revoke
a colleague's, is your console's policy. Pass the acting person as `ApiKeyActor` so the
audit trail records them.

Every issue and revocation writes an audit entry (`api_key.created`, `api_key.revoked`,
target type `customer_api_key`) and emits the webhook event of the same name. The payload
carries `key_id`, `user_id`, `client_id`, `organization_id` and, on creation, the name,
permissions, listing prefix and expiry. It never carries the key.

## Verifying a key: `POST /oauth/api-keys/verify`

Your API receives a request carrying a customer's key. It asks Cbox ID whether the key
is good, authenticating as **itself**, with the same client credentials it uses at the
token endpoint.

```
POST /oauth/api-keys/verify
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/json

{"key": "ctx_live_…"}
```

Client authentication works the same way as at `/oauth/token`: `client_secret_basic`,
`client_secret_post` (`client_id` + `client_secret` in the body) or `private_key_jwt`
(`client_assertion`). Public clients have no credential and are refused.

**Active key, bound to the caller:**

```json
{
  "active": true,
  "key_id": "01j9…",
  "sub": "01j8…",
  "org": "01j7…",
  "org_role": "admin",
  "permissions": ["returns:read"],
  "client_id": "cid_01j6…",
  "expires_at": "2027-09-24T10:00:00Z"
}
```

| Field | Meaning |
|---|---|
| `key_id` | the key's id — log it, show it, revoke by it |
| `sub` | the holder's user id |
| `org` | the organization the key acts in |
| `org_role` | the holder's membership tier there (`owner`, `admin`, `developer`, `member`, `viewer`) |
| `permissions` | what the key may do **now**: its own list intersected with the holder's current permissions for your app |
| `client_id` | your app — always the caller |
| `expires_at` | ISO 8601 UTC, or `null` for a key with no expiry of its own |

**Everything else** gets exactly this, with HTTP 200:

```json
{"active": false}
```

This covers unknown, malformed, revoked and expired keys, another app's key, a holder who
left or was deactivated, and a suspended organization. The endpoint never says which, so
it cannot be used to probe keys. The only other answer is `401 {"error":"invalid_client"}`,
when **your own** credentials are wrong.

Responses are `Cache-Control: no-store`. The endpoint is throttled per caller IP at
`cbox-id.customer_api_keys.verify_per_minute` requests a minute (default 600,
`CBOX_ID_API_KEY_VERIFY_PER_MINUTE`).

### Caching on your side

Verification is on your API's request path. If you cache the answer, the cache length is
how long a revoked key or a demoted holder keeps working. A few seconds is a reasonable
trade. Minutes is a revocation delay you should be able to defend. Never cache
`active: false` for longer than you would cache `active: true`.

## Resource servers

A key is bound to a `client_id`: the app whose declared roles and permissions it carries.
An API that enforces those permissions verifies with that same client's credentials. The
binding is a `WHERE` clause on the lookup, not a check made after it. If keys are ever
bound to an API entity of their own, `CustomerApiKeyService::boundToCaller()` is the one
place that widens, and it stays a query constraint.

## Relation to personal tokens

Personal tokens (`cbid_pat_`) and customer keys share storage and never each other's
rows. Each model carries a global scope for its half. A customer key is refused at
`/user-tokens/introspect`, a personal token is refused at `/oauth/api-keys/verify`, and
neither service can list or revoke the other's rows.

## Testing

`InteractsWithAccess::enableCustomerApiKeys($clientId, 'acme_live')` declares a prefix in
one line. The package's own suite uses it.
