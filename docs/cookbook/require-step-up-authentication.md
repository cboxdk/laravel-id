---
title: Require step-up authentication
weight: 46
description: Make a resource demand a recent or second-factor login (RFC 9470) — the 401 challenge, the re-authorization, the authorize-screen decision and the token that satisfies it.
---

# Require step-up authentication

Some operations need more than a valid token. Deleting an organization, paying an
invoice or reading a vault secret should need a login with a second factor, and often a
recent one. RFC 9470 standardises the round trip:

1. The **resource server** gets a token whose login falls short and answers `401` with
   `error="insufficient_user_authentication"`, naming what it needs: `acr_values` (the
   assurance level) and/or `max_age` (how many seconds old the login may be).
2. The **client** sends the person back to `/authorize` with those two parameters.
3. **`/authorize`** checks the person's session against them. If the login is too old,
   the person signs in again. If it is too weak, they add a second factor.
4. The **token endpoint** issues a token whose `acr` and `auth_time` describe the login
   that actually happened, and the resource server accepts it.

This package provides one value object, `AuthenticationRequirement`, that both ends use.
Both ends then apply the same rules, so the authorization server never issues a token
that the resource server will refuse again.

| Piece | Who |
|---|---|
| `acr` and `auth_time` on access tokens, ID tokens and introspection | this package |
| `max_age` validation at `POST /oauth/par` | this package |
| `AuthenticationRequirement` and `BearerChallenge` | this package |
| The resource server's check and its 401 | you, with the two classes above |
| The `/authorize` decision and the sign-in / second-factor screens | you, with `assessSession()` |

## The vocabulary

`acr` values are the classes in discovery's `acr_values_supported`:

| Value | Meaning |
|---|---|
| `urn:cbox-id:aal1` | A single factor (password, social sign-in, SSO). |
| `urn:cbox-id:aal2` | A second factor was used at login: the session's `amr` holds `mfa`, `otp` or `passkey`. |

`aal2` satisfies an `aal1` requirement. If a request lists several classes, the strongest
one this server asserts is required. Values this server does not assert are ignored, as
OIDC treats `acr_values`. A requirement that names only foreign values therefore demands
no class at all. Name a class from `acr_values_supported`.

The token's `acr` is always **derived from the login's `amr`**, never copied from what
was requested. A token cannot claim a higher level than the person reached.

## 1. The resource server: check and challenge

Validate the token as you already do (live, audienced to you, right scope). Then ask
whether the login behind it is good enough:

```php
use Cbox\Id\OAuthServer\Enums\AuthenticationContextClass;
use Cbox\Id\OAuthServer\Support\BearerChallenge;
use Cbox\Id\OAuthServer\ValueObjects\AuthenticationRequirement;

// A second factor, within the last five minutes.
$requirement = AuthenticationRequirement::of(AuthenticationContextClass::Aal2, maxAge: 300);

$assessment = $requirement->assessToken($introspection); // the Introspection you validated

if (! $assessment->isSatisfied()) {
    return response()->json(['error' => 'insufficient_user_authentication'], 401,
        $assessment->challenge(BearerChallenge::for($resource))->headers());
}
```

The header follows RFC 9470 §3. Its `max_age` is quoted, as in the RFC's own example:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://acme.example/.well-known/oauth-protected-resource/mcp", error="insufficient_user_authentication", error_description="The requested authentication context (urn:cbox-id:aal2) was not met.", acr_values="urn:cbox-id:aal2", max_age="300"
```

`assessToken()` reads `acr` and `auth_time` from the token's claims, which is the same
`Introspection` the package's introspector returns. It fails closed:

- With `max_age`, a token without `auth_time` counts as **too old**.
- With an `acr` requirement, a token without `acr` (a `client_credentials` token, a
  device-grant token) counts as **not met**.

The challenge always names the **whole** requirement, even when only one half failed. The
client turns the challenge into its next authorization request, so it has to ask for
everything at once.

To build a challenge by hand, use
`BearerChallenge::for($resource)->insufficientUserAuthentication(['urn:cbox-id:aal2'], 300, 'Step up')`,
or the `withAcrValues()` / `withMaxAge()` withers. Status `401` is the caller's to send.

If your resource server reads JWTs directly instead of introspecting, build the
`Introspection` from the verified claims, or call
`$requirement->assess($claims['acr'] ?? null, $claims['auth_time'] ?? null)`.

### Several levels on one resource

Requirements are per operation, not per resource. Reading may need nothing, while
deleting needs `aal2` within five minutes:

```php
$requirement = match ($operation) {
    'tools/call:delete_project' => AuthenticationRequirement::of(AuthenticationContextClass::Aal2, 300),
    'tools/call:pay_invoice' => AuthenticationRequirement::of(AuthenticationContextClass::Aal2),
    default => AuthenticationRequirement::none(),
};
```

## 2. The client: re-authorize

Per RFC 9470 §4, a client that receives the challenge copies `acr_values` and `max_age`
into a new authorization request:

```text
https://acme.example/oauth/authorize?response_type=code&client_id=…&scope=…
    &code_challenge=…&code_challenge_method=S256&resource=https://acme.example/mcp
    &acr_values=urn:cbox-id:aal2&max_age=300
```

Pushed requests (`POST /oauth/par`) carry them the same way. PAR refuses a `max_age`
that is not a non-negative integer with `400 invalid_request`, so the client learns about
the mistake before anyone is sent to sign in.

## 3. `/authorize`: decide, then send the person to the right screen

`/authorize` is your application's. Two calls cover step-up:

```php
use Cbox\Id\OAuthServer\Exceptions\InvalidAuthenticationRequirement;
use Cbox\Id\OAuthServer\ValueObjects\AuthenticationRequirement;

// Read once, from the pushed payload when there is one (RFC 9126: those ARE the request).
try {
    $requirement = AuthenticationRequirement::fromAuthorizationRequest($pushed ?? $request);
} catch (InvalidAuthenticationRequirement $e) {
    return $this->redirectError($redirectUri, $e->error, $state, $e->getMessage()); // invalid_request
}

// …after the person is known to be signed in:
$assessment = $requirement->assessSession($session); // Cbox\Id\Identity\Models\Session

if (! $assessment->isSatisfied()) {
    // prompt=none, or the person already went round once and is still short: tell the client.
    if ($silent || $alreadyRetried) {
        return $this->redirectError($redirectUri, $assessment->authorizationError(), $state,
            $assessment->errorDescription());
    }

    return $assessment->requiresReauthentication()
        ? $this->sendToSignIn($request)          // max_age exceeded: a fresh sign-in
        : $this->sendToSecondFactor($request);   // acr not met: add a factor
}
```

Hold on to the requirement while the person is away. Put `acr_values` and `max_age` back
on the resumed request, or keep the pushed payload, and assess the session **again**
before you issue the code. A consent screen can stay open past `max_age`.

`authorizationError()` returns:

| Shortfall | Error | Remedy |
|---|---|---|
| `max_age` exceeded, or the session cannot be dated | `login_required` (OIDC Core §3.1.2.6) | Sign in again. |
| Requested class not reached | `unmet_authentication_requirements` (RFC 9470 §5) | Sign in with a second factor. |

If both fall short, the age wins: a fresh sign-in can bring the second factor with it.
`insufficient_user_authentication` is never the answer here, because that error belongs
to the resource server.

Then issue the code **from the session**, exactly as before:

```php
$code = app(AuthorizationCodes::class)->issue(
    $client->client_id, $userId, $organizationId, $redirectUri, $scopes,
    $codeChallenge, 'S256', $nonce,
    $session->created_at?->getTimestamp(),   // → auth_time
    array_values($session->amr),             // → acr, derived
    $resource,
    sessionId: $session->id,
);
```

Nothing else is stored on the code. The token endpoint derives `acr` from the `amr`, so a
password-only session can never produce an `aal2` token, whatever was requested.

### `max_age` leeway

`AuthenticationRequirement::DEFAULT_MAX_AGE_LEEWAY_SECONDS` (60) is added to `max_age` on
both sides. It covers the redirect between a fresh sign-in and the resumed request, the
time until the token reaches the resource, and clock skew. Without it, `max_age=0` could
never be met. Both `assess*()` methods take a `leeway` argument. If you change it, use the
same value on both sides.

### `prompt=login`

`prompt=login` is not part of the requirement. It asks for a sign-in during **this**
request, and only your flow knows whether one happened, so handle it there as you do today.

## 4. The token that satisfies it

| | Access token | ID token | Introspection |
|---|---|---|---|
| `acr` | when the login recorded `amr` | when the login recorded `amr` | when the token carries it |
| `auth_time` | when the login is known | when the login is known | when the token carries it |

Which grants carry them:

- **Authorization code, and every refresh of one:** both. A refresh keeps the
  **original** login's values (RFC 9470 §6.1, OIDC Core §12.2). A refreshed token is
  never fresher than its login, so a resource with a `max_age` sends the client back to
  `/authorize` once the login ages out, however recently the token was refreshed.
- **CIBA:** `auth_time` (the approval time), no `acr`. The approval records no
  authentication methods.
- **Device code, token exchange, support sessions:** neither. Nobody's login is recorded
  on those grants, so a resource that requires step-up refuses them.
- **`client_credentials`:** neither. There is no person.

Both claims are **reserved**, so a token-minting hook cannot add or change them.

## Testing

```php
use Cbox\Id\OAuthServer\ValueObjects\AuthenticationRequirement;
use Cbox\Id\OAuthServer\ValueObjects\Introspection;

it('demands a second factor for deletion', function (): void {
    $token = Introspection::active('user_1', 'cid', ['mcp:write'], ['acr' => 'urn:cbox-id:aal1', 'auth_time' => time()]);

    $assessment = AuthenticationRequirement::of('urn:cbox-id:aal2')->assessToken($token);

    expect($assessment->requiresStepUp())->toBeTrue()
        ->and($assessment->challenge()?->header())->toContain('error="insufficient_user_authentication"');
});
```

## Limits

- **Two levels.** `aal1` and `aal2` are vendor URNs, not standard assurance-level
  identifiers. There is no phishing-resistant-only class, so a passkey and a one-time code
  both count as `aal2`.
- **No `claims` parameter.** An `acr` requested as an essential claim
  (`claims={"id_token":{"acr":{"essential":true,…}}}`) is not read, and discovery
  advertises `claims_parameter_supported: false`. Use `acr_values`.
- **The resource server's half is code you write.** The package has no route middleware
  for your own endpoints. The check above is three lines inside the guard you already have.
- RFC 9728 protected resource metadata has no field for a resource's authentication
  requirements, so nothing is advertised there. Requirements reach the client only through
  the challenge.
