---
title: Frontend API & publishable keys
description: The browser-facing channel — a public key bound to an origin allow-list, so a page can read its own sign-in configuration without a server in the middle
weight: 15
---

# Frontend API & publishable keys

Every credential this package issues is a secret: a client secret, an API key, a
service-account credential. They share one rule — *never put this in a browser* — and
that rule is why an SDK component cannot draw a sign-in box. A page that cannot
authenticate itself to the identity provider cannot ask it anything, so it sends the
person away to a hosted page and waits for them to come back.

A **publishable key** inverts the rule deliberately. It is public. It ships in a JS
bundle, it is visible in devtools, it is in the page source of every customer who uses
it — and none of that is a compromise, because it authenticates almost nothing.

## What makes a public key safe

The key names an environment and says *a browser is asking*. That is all it does.

The security comes from somewhere else: **every key carries an allow-list of origins**,
and a request whose `Origin` header is not on that list is refused before anything else
runs. A key that leaks is a key that still only works from the sites its owner named.

This is the same shape as Stripe's publishable key plus registered domains, and for the
same reason.

Three properties follow, and each is load-bearing:

- **The comparison is byte-for-byte.** Not a suffix match, not a wildcard, not "starts
  with https://". Every subtle version of this check has been somebody's vulnerability:
  a suffix match treats `https://acme.com.evil.test` as `https://acme.com`.
- **Origins are normalized when they are stored**, never when a request arrives. A
  browser sends a serialized origin — lowercase scheme and host, port only when it is not
  the default, no path, no trailing slash. What a person types is turned into that form
  once, on the way in, so nothing at request time has to be lenient.
- **A refusal carries no CORS headers.** The browser sees a CORS failure rather than a
  readable error, because a page has no business reading the body of a rejection it was
  not authorized to make. The developer sees the real reason in the network tab.

## Turning it on

Off by default. An install that has named no origins should not be answering browsers,
and a browser-facing surface that appears silently on upgrade is one nobody reviewed.

```dotenv
CBOX_ID_FRONTEND_API=true
```

That serves `/frontend/v1/*` on whichever host the environment resolves on.

## Issuing a key

```php
use Cbox\Id\FrontendApi\Contracts\PublishableKeys;
use Cbox\Id\FrontendApi\Enums\KeyMode;

$key = app(PublishableKeys::class)->issue(
    name: 'Marketing site',
    mode: KeyMode::Live,
    origins: ['https://acme.com', 'https://www.acme.com'],
);

$key->key; // pk_live_XcE1…  — paste this into the bundle
```

Origins are part of minting rather than a later step: a key with no origins works
nowhere, and creating one, copying it into a bundle and *then* discovering it is inert is
a support ticket every time.

**An unusable origin throws.** It is not skipped — an allow-list that quietly drops the
entry somebody typed leaves them holding a key that does not work and no reason why.

**Plain `http` is refused away from loopback.** A key travelling in the clear can be
lifted by anyone on the path. `http://localhost:3000` is allowed, because it is where
every integration begins and it is the one place a browser treats an insecure origin as
trustworthy.

**Two modes, in the key itself.** `pk_test_` and `pk_live_` are different keys against
different environments, so a person reading a diff or a bundle can see which one they are
looking at. A single key plus a boolean elsewhere is one config mistake away from a
staging page driving production sign-ins.

## Calling it

```js
const res = await fetch('https://id.acme.com/frontend/v1/config', {
  headers: { 'X-Cbox-Publishable-Key': 'pk_live_XcE1…' },
})
```

The key goes in a **header, never a query string**. A query string would put it in server
logs, in `Referer` on every outbound link, and in browser history — and while the key is
public, spraying it through logs makes revocation harder to reason about and makes the
key look like a secret that leaked.

### `GET /frontend/v1/config`

Everything needed to *draw* a sign-in box, and nothing that identifies anybody.

```json
{
  "mode": "live",
  "issuer": "https://id.acme.com",
  "endpoints": {
    "authorization": "https://id.acme.com/oauth/authorize",
    "token": "https://id.acme.com/oauth/token",
    "userinfo": "https://id.acme.com/oauth/userinfo",
    "end_session": "https://id.acme.com/oauth/logout",
    "jwks": "https://id.acme.com/.well-known/jwks.json"
  },
  "social": [{ "provider": "google", "name": "Google" }]
}
```

Cached privately for a minute — long enough that a page with several components fetches
it once, short enough that flipping a provider on shows up while somebody is still
looking at the console. Never in a shared cache: the document differs per environment.

### `GET /frontend/v1/session`

Who the browser is signed in as, shaped for a component to draw.

```js
const res = await fetch('https://id.acme.com/frontend/v1/session', {
  headers: {
    'X-Cbox-Publishable-Key': 'pk_live_XcE1…',
    Authorization: `Bearer ${accessToken}`,
  },
})
// { "user": { "id": "…", "email": "…", "name": "…" } }  or  { "user": null }
```

**Signed out is a state, not an error.** It answers `{"user": null}` with a 200, because
a component like `<UserButton/>` renders on every page including the ones nobody has
signed in on — and forcing it to treat 401 as a state is how flash-of-signed-out bugs are
born.

**The publishable key grants nothing here.** The bearer token is the entire authority; the
key only got the request through the door and said which environment to look in. A page
holding a key and no token learns nothing about anybody, which is the property that makes
the key safe to publish.

## What this package serves, and what it does not

**Those two endpoints are the whole of it.** `config` and `session` — nothing else on
`/frontend/v1/*` comes from here.

That matters because the SDKs offer more than two calls. `@cboxdk/id-js` has `signIn()`,
and `@cboxdk/id-react`'s `<SignIn/>` component drives it; between them they post to
`/frontend/v1/sign-in`, `/frontend/v1/sign-in/factor`,
`/frontend/v1/sign-in/passkey/options` and `/frontend/v1/sign-in/passkey`. **A bare
`cboxdk/laravel-id` install answers 404 to all four** — and from a browser a 404 on a
cross-origin request is indistinguishable from the network being down, so the SDK reports
a connection failure and the cause is invisible.

The split is deliberate rather than an omission. Those endpoints take a password, decide
whether a second factor is owed, and mint a single-use login ticket: they *are* the
sign-in policy, and this package no more owns your sign-in policy than it owns your login
page. The reference implementation is in
[`cboxdk/cbox-id`](https://github.com/cboxdk/cbox-id) — `routes/web.php`, under the
`frontend/v1` prefix. A host that wants the embedded sign-in either runs that or
implements the same four routes.

If you only need to draw the environment's theme and read who is signed in — which is what
`useCboxConfig()` and `<UserButton/>` do — this package is enough on its own.

## What may never go on this channel

The temptation is real for each of these, and each is one array merge away.

- **Anything keyed on an email or a user id.** "Does this account exist" is the
  enumeration oracle every identity product eventually leaks, and a public endpoint is
  the easiest place to leak it. Per-user method discovery belongs behind an authenticated
  flow.
- **Counts, names or ids** of organizations, users or connections beyond what a button
  needs to render. A competitor holding a publishable key should learn nothing about the
  size or shape of the estate.
- **Anything an operator configured privately** — webhook URLs, SCIM state, connection
  config.

The rule for anything new: *would I put this in the page source?* If not, it does not go
here.

## Adding your own fields

The package does not know what branding is, and should not learn — appearance lives in
the application. Register a contributor:

```php
use Cbox\Id\FrontendApi\Contracts\FrontendConfigContributor;

class AppearanceConfig implements FrontendConfigContributor
{
    public function contribute(array $config): array
    {
        $config['appearance'] = /* your tokens */;

        return $config;
    }
}

// In a service provider:
$this->app->tag(AppearanceConfig::class, FrontendConfigContributor::class);
```

Everything contributed is public. A contributor that adds something conditioned on *who
is asking* has misunderstood the channel — nobody is asking yet.

## Rate limiting

600 requests a minute per key. Generous, because a single page load legitimately makes
several and a customer's whole traffic shares one key: it is a ceiling against loops and
scraping, not a quota. Limiting is applied **after** the key and origin are verified, so
one abusive caller cannot exhaust a bucket shared with legitimate ones.

## Revoking

```php
app(PublishableKeys::class)->revoke($keyId);
```

Revocation is a timestamp rather than a delete, so a key that turns up in a log six
months from now can still be identified as one you withdrew, and when. Re-revoking keeps
the original timestamp — when a key stopped working is a fact somebody needs during an
incident, and overwriting it with the time of the second click destroys it.

`last_used_at` is written at most once a minute, and is what tells you whether a key is
still wired into something before you revoke it.
