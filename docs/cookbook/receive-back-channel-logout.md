---
title: Receive back-channel logout
weight: 44
description: When a person signs out, every application they used is told server to server. Wire the host once, then have each app validate the logout token and end its session.
---

# Receive back-channel logout

When a person signs out, when an administrator ends their sessions, when their account is
deactivated, or when they are removed from an organization, every application that signed
them in is told — by a signed **logout token** POSTed from the server to the application
(OpenID Connect Back-Channel Logout 1.0). The application ends its own session for them.
It does not need to re-check the person's grants on every request to find out.

There are two halves: the host that runs this package names the session a sign-in came
from, and each application registers an endpoint and validates what arrives there.

## The host: name the session

The ID Token's `sid` and the record of which applications a session reached both come from
one argument. Pass the session id when you mint the authorization code:

```php
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;

$code = app(AuthorizationCodes::class)->issue(
    $clientId,
    $userId,
    $organizationId,
    $redirectUri,
    $scopes,
    $codeChallenge,
    'S256',
    $nonce,
    $session->created_at?->getTimestamp(),
    $session->amr,
    $resource,
    sessionId: $session->id,   // the SessionManager session the person approved from
);
```

Without it everything still works, and the application is still reachable by `sub` when
the person signs out everywhere or loses access — but no ID Token carries `sid`, and ending
one session cannot name it.

Sessions ended through `SessionManager` — `revoke()` and `revokeAllForUser()` — notify the
applications on their own. So do `RefreshTokens::revokeForUser()` /
`revokeForUserAndClient()`, `Subjects::deactivate()`, and removing a membership. A host that
ends sessions some other way calls the contract itself:

```php
use Cbox\Id\OAuthServer\Contracts\BackchannelLogout;

app(BackchannelLogout::class)->sessionEnded($sessionId);   // one session
app(BackchannelLogout::class)->subjectSignedOut($userId);  // every session they hold
```

These only record and queue: delivery runs on a **queue worker** (see
[Background work](../operations/background-work.md)), so an application that is down never
slows a sign-out.

### RP-initiated logout without an `id_token_hint`

`/oauth/logout` without a verifiable hint may only sign out *this browser*. The package
cannot know where your host keeps this browser's session id, so by default it clears the
Laravel session and leaves the session row alone — and then no application hears about it.
Bind `SignedInSession` and that logout ends the session properly:

```php
use Cbox\Id\Identity\Contracts\SignedInSession;

$this->app->singleton(SignedInSession::class, MySignedInSession::class);

class MySignedInSession implements SignedInSession
{
    public function id(): ?string
    {
        // Only from what this browser has already proven — never a request parameter.
        return session('platform.session_id');
    }
}
```

### Register the application

```php
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;

app(ClientRegistry::class)->configureBackchannelLogout(
    $client,
    'https://app.example.com/auth/backchannel-logout',
    sessionRequired: false,
);
```

Or at registration: `NewClient(backchannelLogoutUri: …, backchannelLogoutSessionRequired: …)`,
or `backchannel_logout_uri` / `backchannel_logout_session_required` in a Dynamic Client
Registration request. The URI must be `https://` (plain `http://` only on `localhost`), with
no fragment and no credentials. It is checked again at delivery by the SSRF guard: a host
that resolves to a private, loopback or metadata address is never called, so a
`localhost` URI is only reachable with `CBOX_ID_BACKCHANNEL_LOGOUT_VERIFY_URL=false`, in
development.

Set `sessionRequired` when your application can only end a session it can name. Such an
application receives one token per session, always with `sid`, and never a subject-only one.

## The application: validate and end the session

The request is a `POST` with `Content-Type: application/x-www-form-urlencoded` and one
field, `logout_token`. Validate it the way you validate an ID Token, plus the logout-specific
checks (§2.6):

1. Verify the signature against the issuer's JWKS (`/.well-known/jwks.json`), with the
   algorithm pinned to `RS256` — the same key and algorithm as the ID Token.
2. `iss` is the issuer you signed in against; `aud` is your `client_id`.
3. `iat` is present and recent; `exp` has not passed (tokens live two minutes).
4. `typ` in the header is `logout+jwt`.
5. `events` contains the member `http://schemas.openid.net/event/backchannel-logout`.
6. `sub`, `sid`, or both are present.
7. There is **no** `nonce` — a token with one is refused, so an ID Token can never be
   replayed here.
8. `jti` has not been seen before (keep it until `exp`).

Then end the session: by `sid` when present, otherwise every session of `sub`. Answer
`200` (or `204`) with `Cache-Control: no-store`; answer `400` for a token you refused.

A Laravel application using `firebase/php-jwt`:

```php
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;

Route::post('/auth/backchannel-logout', function (Request $request) {
    $issuer = config('services.cbox_id.issuer');     // e.g. https://id.example.com
    $clientId = config('services.cbox_id.client_id');

    $refuse = fn (string $why) => response()->json(['error' => 'invalid_request', 'error_description' => $why], 400)
        ->header('Cache-Control', 'no-store');

    $token = (string) $request->input('logout_token');

    try {
        $jwks = Cache::remember('cbox-id.jwks', 3600, fn () => Http::get($issuer.'/.well-known/jwks.json')->throw()->json());
        $claims = (array) JWT::decode($token, JWK::parseKeySet($jwks, 'RS256'));  // signature, exp, iat
    } catch (\Throwable) {
        return $refuse('invalid token');
    }

    $header = json_decode(JWT::urlsafeB64Decode(explode('.', $token)[0]), true);
    $events = (array) ($claims['events'] ?? []);

    if (($header['typ'] ?? null) !== 'logout+jwt'
        || ($claims['iss'] ?? null) !== $issuer
        || ! in_array($clientId, (array) ($claims['aud'] ?? []), true)
        || ! array_key_exists('http://schemas.openid.net/event/backchannel-logout', $events)
        || (! isset($claims['sub']) && ! isset($claims['sid']))
        || array_key_exists('nonce', $claims)) {
        return $refuse('not a logout token for this client');
    }

    // Replay: each jti once, for as long as the token could be valid.
    if (! Cache::add('backchannel-jti:'.$claims['jti'], true, 300)) {
        return $refuse('replayed');
    }

    // Your session store: you recorded `sid` (and `sub`) from the ID Token at sign-in.
    isset($claims['sid'])
        ? MySessions::endBySid($claims['sid'])
        : MySessions::endAllForSubject($claims['sub']);

    return response('', 200)->header('Cache-Control', 'no-store');
});
```

**Record `sid` at sign-in.** Store the ID Token's `sid` and `sub` against the session you
create. That is what `endBySid` looks up — the logout token carries no other reference to
your session. On Laravel's `database` session driver this is typically a column or a small
table from `sid` to your session ids.

**Exclude the route from CSRF.** The request comes from a server, with no session and no
token. Exclude the path in `bootstrap/app.php` —
`$middleware->validateCsrfTokens(except: ['auth/backchannel-logout'])` — rather than with
`withoutMiddleware(VerifyCsrfToken::class)` on the route, which does not match the
middleware Laravel 11+ actually registers and so excludes nothing.

## When a delivery fails

Every final outcome is in the environment's audit trail: `oauth.backchannel_logout.delivered`,
or `oauth.backchannel_logout.failed` with the reason — `HTTP 400: invalid_request`,
`connection failed: …`, `backchannel_logout_uri refused by the SSRF guard: …`. Timeouts,
`5xx`, `408` and `429` are retried (10 s, 1 min, 5 min, 15 min…, five attempts by default);
any other `4xx`, a redirect, or an SSRF refusal is final.
