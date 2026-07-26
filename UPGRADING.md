---
title: Upgrading
description: Breaking changes and the migration each one needs, newest first
weight: 3
---

# Upgrading

Breaking changes only, newest first. Everything else is in [`CHANGELOG.md`](CHANGELOG.md).

The entries here are the ones that change behaviour for a deployment that is already
running. Read the whole section for the version you are crossing before you deploy — two
of the changes below fail **silently** (nothing is logged, nothing 500s) and one of them
fires on clients you do not control.

## Unreleased (from 0.56.x)

### Do this BEFORE you deploy

1. **Run a queue worker.** Webhook delivery is no longer synchronous.
2. **Audit every registered client's scope list.** `invalid_scope` is now enforced at
   `/authorize`. This has the widest blast radius in the release.
3. **On PostgreSQL, reconcile case-variant duplicate usernames/emails.** Equality is now
   case-insensitive on every driver, so rows that used to coexist now collide.
4. **Re-read your published `config/cbox-id.php`.** Package defaults are now merged
   key-by-key instead of block-by-block, so settings a partial published config used to
   suppress are live again.

Each is expanded below.

---

### Webhooks require a running queue worker — SILENT if missing

**What changed.** `HttpWebhookDispatcher` used to make the outbound HTTP request in-band,
inside the relay pass. It now dispatches a `DeliverWebhook` job. The relay's job is to
enqueue; the worker's job is to deliver.

**Why.** One endpoint that accepts the connection and never answers used to hold the relay
pass open, delaying every other tenant's events behind it. Delivery also had no way to
recover a request the process died in the middle of.

**How it breaks.** A deployment with no worker consuming the queue enqueues jobs that are
never run. Deliveries sit at `pending`. **No exception is thrown and nothing is logged as
an error** — from the console the endpoint simply looks quiet. This is the failure mode
most likely to be mistaken for "no events happened".

**What to do.**

```sh
php artisan queue:work --queue=default
```

Run it under a supervisor (systemd, Supervisor, Horizon) so it restarts. If you already
run a worker for the framework's own queues, webhook jobs go on the same connection unless
you separate them:

```env
CBOX_ID_WEBHOOKS_QUEUE_CONNECTION=redis
CBOX_ID_WEBHOOKS_QUEUE=webhooks
```

`QUEUE_CONNECTION=sync` also "works" and restores the old inline behaviour — but it
reintroduces the head-of-line blocking the change exists to remove, so treat it as a
development setting only.

**How to check you got it right.** After deploying, trigger any event and confirm the
delivery leaves `pending`. `php artisan cbox-id:events:backlog --json` reports outbox depth;
a depth that only grows means the relay or the worker is not running.

See [Background work](docs/operations/background-work.md) for the full picture, including
the retry sweep, the stranded-delivery rescue and the per-endpoint circuit breaker.

### The root host now 404s the IdP surface

**What changed.** The protocol surface — OIDC discovery, JWKS, `/oauth/*`, SCIM — is now
behind a configurable middleware gate (`cbox-id.api.middleware`). In a multi-tenant
deployment the apex host refuses it.

**How it breaks.** A client pointed at the apex rather than at its environment's issuer
gets a `404`, where it previously got a working response. This looks exactly like an
outage.

**What to do.** Point clients at the issuer that discovery advertises, never at the apex.
The gate is inert in a single-tenant install (`cbox-id.api.middleware` defaults to `[]`),
so nothing changes there. See the deployment docs in the app repo for the host layout.

**Note:** `GET /up` is registered outside the gated group and still answers on every host,
so a liveness probe against the apex is unaffected.

### `invalid_scope` is enforced at `/authorize` — widest blast radius

**What changed.** A scope the client is not registered for used to be accepted at
`/authorize` and then quietly filtered out when the token was minted. It is now refused up
front with `error=invalid_scope`.

**Why.** The old behaviour turned a registration mistake into a mystery: the authorization
succeeded, the token came back missing a scope, and the client's next API call failed with
a 403 that nothing anywhere explained.

**How it breaks.** **Every deployed client whose SDK requests more scopes than it
registered now hard-fails at the authorize step instead of degrading.** You do not control
when those clients next run, and you cannot fix them from the server side after the fact.
The usual culprits are `email` and `offline_access` — SDK defaults that were never added to
the registration.

**What to do — before you deploy.** For every client, compare its registered scope list
against what its SDK actually sends:

```sh
php artisan tinker
>>> \Cbox\Id\OAuthServer\Models\Client::query()->get(['client_id', 'name', 'scopes']);
```

Add any scope that is legitimately requested. A client registered with **no** scopes at all
is exempt from the check — it has declared no surface to validate against — so an empty
list is not a false positive.

**Related, non-breaking:** `/oauth/token` now echoes the granted `scope` in its response, so
a narrowed grant is visible at the point it happens.

### SAML: stricter `AuthnRequest` handling

Four changes, all refusals that used to be acceptances:

- **`NameIDPolicy` is enforced** against what the registered SP can actually be answered
  under. A policy the registration does not support is refused instead of being answered
  under a different format. (`urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified` still
  means "IdP, you choose".)
- **A signed `AuthnRequest` must carry a `Destination`.** A signed request with no
  `Destination` at all was previously accepted; it is now refused, because the signature
  then covers no statement about where the request was meant to go.
- **An `AuthnRequest` is single-use.** A replayed request id is refused.
- **An `AuthnRequest` older than 15 minutes is refused.**

**What to do.** If an SP integration starts failing, the refusal reason is in the audit
trail. A relying party that cannot supply `Destination` on a signed request must either
stop signing or be fixed; there is no configuration switch to re-accept it.

### SCIM: stricter errors, and one response-shape change

| Case | Before | Now |
|---|---|---|
| `DELETE` an id that does not exist | `204` | `404` |
| `PATCH` with malformed or absent `Operations` | `200` (silently no-op) | `400` |
| `active` sent as a non-boolean (`"fasle"`, `"no"`, `0`, `1`) | `200`, treated as false | `400` |
| Rate limited | plain framework `429` | `429` inside the SCIM Error envelope, `Retry-After` intact |
| `GET /Groups` (listing) | included `members` | **omits `members`** unless requested |
| Filter literal of the wrong type for its attribute | matched nothing, `200` | `400 invalidFilter` |

The `/Groups` change is the one that can break a working integration: a client that reads
membership from the listing now sees no members. Ask for them explicitly
(`?attributes=members`), or read the group singly — a single-resource `GET /Groups/{id}`
still returns members. The change exists because a page of large groups was a memory bomb.

The stricter errors are a net win for integrators (a rejected write is now visible instead
of being reported as a success it did not make), but a connector that treats any non-2xx as
fatal will start alerting on requests it used to send happily.

See [SCIM](docs/core-concepts/scim.md) for the full endpoint reference.

### `userName` / email equality is case-insensitive on ALL drivers

**What changed.** Comparison used to depend on the database's collation: case-insensitive
on MySQL's default collation, case-**sensitive** on PostgreSQL. It is now case-insensitive
everywhere, via normalized columns
(`2026_07_25_000100_add_normalized_scim_columns_to_directory_users`).

**How it breaks.** **A PostgreSQL tenant may hold rows that were legal before and are not
now** — `Alice@example.com` and `alice@example.com` as two separate directory users. After
the migration they collide, and a create or update that touches either returns
`409 uniqueness`.

**What to do — before you deploy.** Find the duplicates and merge or delete them:

```sql
SELECT directory_id, lower(user_name) AS key, count(*)
FROM directory_users
GROUP BY directory_id, lower(user_name)
HAVING count(*) > 1;

SELECT directory_id, lower(email) AS key, count(*)
FROM directory_users
WHERE email IS NOT NULL
GROUP BY directory_id, lower(email)
HAVING count(*) > 1;
```

The migration backfills `user_name_lower` / `email_lower` and indexes them; it does NOT
deduplicate. Decide which row survives for each collision —
this is a data decision, not a mechanical one, because the two rows may carry different
memberships. The migration itself does not merge them for you.

### `/up` returns JSON

`GET /up` now returns `{"status":"ok"}` with `Content-Type: application/json` instead of an
empty body. A probe asserting on an empty body or on `text/html` needs updating; a probe
asserting only on the status code is unaffected.

### Published config is merged key-by-key, not block-by-block

**What changed.** The package used to merge its defaults with Laravel's
`mergeConfigFrom()`, a single `array_merge()` that only merges the TOP level. It now uses
`Cbox\Id\Support\PackageConfigMerger`, which recurses.

**Why.** A published `config/cbox-id.php` is almost always PARTIAL — you override one
setting and delete the rest of the file. Under the old merge, naming a top-level key
replaced the package's ENTIRE block for that key. An app whose config declared nothing but

```php
'oauth' => ['authorization_endpoint_path' => '/oauth/authorize'],
```

silently lost `oauth.access_token_ttl`, `oauth.require_par`, `oauth.embed_entitlements`,
`oauth.decisions.*`, `oauth.ciba.*`, `oauth.dynamic_registration.*` and
`oauth.authorization_endpoint`. Every consumer inside the package passes a hard-coded
fallback to `config()`, so nothing crashed — but `CBOX_ID_ACCESS_TOKEN_TTL`,
`CBOX_ID_REQUIRE_PAR`, `CBOX_ID_DCR_MODE`, `CBOX_ID_DECISIONS_MAX_BATCH` and
`CBOX_ID_CIBA_*` were **inert**. Setting them did nothing and said nothing.

**The rules.**

- Your value wins on any key you define, including `null`, `false` and `0`.
- A package default is only ever filled in where your config is SILENT about that key.
- A **list** (sequential array — `api.middleware`, `oauth.dynamic_registration.allowed_scopes`)
  is treated as a single value: yours REPLACES the package's, it is never appended to. You
  can still shrink a default list, or empty it with `[]`.
- Where your value and the package's are different types, yours stands unmerged.

**How it breaks you.** Only in one shape: if you were relying on the shallow merge to
REMOVE a package default — omitting a sibling key so it disappeared entirely — that key is
now present again at its package default. Check any top-level block you published
partially. Package defaults are conservative (DCR `disabled`, PAR not required), so the
usual effect of getting them back is that an env var you set now takes effect. To keep a
default suppressed, state it explicitly:

```php
'oauth' => [
    'authorization_endpoint_path' => '/oauth/authorize',
    'embed_entitlements' => false, // explicit beats omitted
],
```

`php artisan cbox-id:doctor` and `php artisan config:show cbox-id` both print the merged
result, which is the fastest way to see what your deployment actually resolves.

---

## How to read this file

An entry earns a place here only if a deployment that was working can stop working, or
start behaving differently, without anyone changing their own code. Additive features,
new endpoints and bug fixes that only ever made a wrong answer right live in
[`CHANGELOG.md`](CHANGELOG.md).
