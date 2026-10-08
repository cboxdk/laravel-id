---
title: Protect an MCP server with Cbox ID
weight: 45
description: Declare your MCP endpoint as a protected resource, let MCP clients register or bring a metadata document, and accept only tokens audienced to it.
---

# Protect an MCP server with Cbox ID

The MCP authorization model is OAuth 2.1 with four standards on top: the resource server
publishes **protected resource metadata** (RFC 9728) and points at it from its 401; the
client either **registers itself** (RFC 7591) or presents a **client ID metadata document**
URL; it runs the authorization code flow with **PKCE**; and it names the MCP server with
**`resource`** (RFC 8707) so the token it gets back is good there and nowhere else.

This package is the authorization server half. Your application serves the MCP endpoint
and `/authorize`; this page is the glue between them.

## What you get, and what you write

| Piece | Who |
|---|---|
| RFC 8414 metadata, PAR, `/oauth/token`, `/oauth/register`, JWKS | this package |
| RFC 9728 document for your MCP endpoint | this package, once you declare the endpoint |
| `resource` → `aud`, refresh bound to it, `invalid_target` for anything else | this package |
| Fetching and validating client ID metadata documents (SSRF-guarded) | this package |
| The MCP endpoint itself and its 401 | you — with `BearerChallenge` |
| `/authorize`, sign-in and the consent screen | you — with `AuthorizationClients` |

## 1. Configure

```php
// config/cbox-id.php
'oauth' => [
    // Where your /authorize lives, joined to each environment's issuer. Without it the
    // discovery document advertises no code flow at all.
    'authorization_endpoint_path' => '/oauth/authorize',

    // Your MCP endpoint, at https://{host}/mcp in every environment.
    'protected_resources' => [
        [
            'path' => '/mcp',
            'name' => 'MCP',
            'scopes' => ['mcp:read', 'mcp:write'],
            'dynamic_clients' => true,   // MCP clients register themselves
        ],
    ],

    // Open registration, held to the MCP profile: public clients, PKCE, https or loopback
    // redirect URIs, and only the scopes declared above (plus allowed protocol scopes).
    'dynamic_registration' => [
        'mode' => 'mcp',
        'max_per_ip_per_hour' => 20,
    ],

    // Optional: accept an https URL as client_id and read the client from it.
    'client_id_metadata_documents' => [
        'enabled' => true,
    ],
],

'prune' => [
    'retention_days' => [
        // Sweep self-registered clients nobody has used in 30 days.
        'oauth_clients' => 30,
    ],
],
```

The endpoint is now described at `https://{host}/.well-known/oauth-protected-resource/mcp`:

```json
{
  "resource": "https://acme.example/mcp",
  "authorization_servers": ["https://acme.example"],
  "scopes_supported": ["mcp:read", "mcp:write", "offline_access"],
  "bearer_methods_supported": ["header"],
  "resource_name": "MCP"
}
```

When the list depends on more than config — a plan, a feature flag — bind your own
`Cbox\Id\OAuthServer\Contracts\ProtectedResources` instead.

## 2. Guard the MCP endpoint

Accept a token only if it is live **and audienced to this endpoint**. Every refusal is a 401
whose `WWW-Authenticate` carries `resource_metadata`, which is how an MCP client that knows
nothing but your URL finds everything else.

```php
use Cbox\Id\OAuthServer\Contracts\ProtectedResources;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Dpop\DpopResourceGuard;
use Cbox\Id\OAuthServer\Support\BearerChallenge;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class AuthenticateMcp
{
    public function __construct(
        private readonly ProtectedResources $resources,
        private readonly TokenIntrospector $tokens,
        private readonly DpopResourceGuard $dpop,
    ) {}

    public function handle(Request $request, Closure $next, string $scope = 'mcp:read'): Response
    {
        // Looked up by path, so it is this environment's /mcp whatever host or proxy
        // the request arrived through.
        $resource = $this->resources->forMetadataPath('/.well-known/oauth-protected-resource/mcp')
            ?? abort(404);
        $challenge = BearerChallenge::for($resource);

        $token = $this->dpop->bearer($request);
        $introspection = $token === null ? null : $this->tokens->introspect($token);

        // `isAudience()` alone treats a token with no `aud` as first-party; every token
        // this package mints carries one, so require it outright.
        if ($introspection === null || ! $introspection->active
            || ! isset($introspection->claims['aud'])
            || ! $introspection->isAudience($resource->identifier)) {
            return response()->json(['error' => 'invalid_token'], 401,
                $challenge->withError('invalid_token')->headers());
        }

        if (! $introspection->hasScope($scope)) {
            return response()->json(['error' => 'insufficient_scope'], 403,
                $challenge->withError('insufficient_scope')->withScopes([$scope])->headers());
        }

        $request->attributes->set('mcp.subject', $introspection->subject);

        return $next($request);
    }
}
```

### Tools that need a stronger login

A live, audienced, scoped token can still come from a password-only login made
yesterday. For tools that delete or pay, also check the login behind the token. Answer
`401` with the RFC 9470 challenge, and the MCP client re-authorizes with `acr_values` and
`max_age`:

```php
use Cbox\Id\OAuthServer\Enums\AuthenticationContextClass;
use Cbox\Id\OAuthServer\ValueObjects\AuthenticationRequirement;

$stepUp = AuthenticationRequirement::of(AuthenticationContextClass::Aal2, maxAge: 300)
    ->assessToken($introspection);

if (! $stepUp->isSatisfied()) {
    return response()->json(['error' => 'insufficient_user_authentication'], 401,
        $stepUp->challenge($challenge)->headers());
}
```

Your `/authorize` then has to honour those two parameters. See
[Require step-up authentication](require-step-up-authentication.md).

## 3. Handle the MCP client at `/authorize`

Three calls cover what is new: resolve the client (registered or described by a document),
read the one `resource`, and ask the audience resolver whether that client may be audienced
there — the same resolver the token endpoint asks, so `/authorize` can never accept what
redemption would refuse.

```php
use Cbox\Id\OAuthServer\Contracts\AudienceResolver;
use Cbox\Id\OAuthServer\Contracts\AuthorizationClients;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Exceptions\InvalidAudience;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadataDocument;
use Cbox\Id\OAuthServer\Support\ResourceParameter;

// $pushed is the consumed PAR payload, or null for a plain query request.
try {
    $authorizing = app(AuthorizationClients::class)->resolve((string) $clientId);
} catch (InvalidClientMetadataDocument $e) {
    // No verified redirect URI yet: render, never redirect (RFC 6749 §4.1.2.1).
    return $this->failure($e->getMessage());
}

if ($authorizing === null || ! $authorizing->allowsRedirectUri((string) $redirectUri)) {
    return $this->failure('Unknown client or redirect URI.');
}

try {
    // One resource per request; a repeated one is invalid_target. PAR already validated
    // the pushed value, and fromValue() reads it the same way.
    $resource = $pushed !== null
        ? ResourceParameter::fromValue($pushed['resource'] ?? null)
        : ResourceParameter::fromRequest($request);

    $granted = app(AudienceResolver::class)->resolve(
        $authorizing->client,
        array_values(array_filter($requestedScopes, $authorizing->client->allows(...))),
        $resource,
    );
} catch (InvalidAudience $e) {
    return $this->redirectError($redirectUri, $e->error, $state, $e->getMessage());
}

// $granted->scopes is what the token will carry — show those on the consent screen.
// Never skip consent for a self-registered client:
$mustAsk = $authorizing->consentRequired() || ! $this->firstPartySkip($authorizing->client);

// For a metadata document client, lead with the verified host, not the self-declared name:
//   "{$authorizing->documentHost} wants to use MCP on your behalf"
```

Once the person approves, bind the code to the resource:

```php
$code = app(AuthorizationCodes::class)->issue(
    $authorizing->client->client_id, $userId, $organizationId, $redirectUri,
    $requestedScopes, $codeChallenge, resource: $resource,
);
```

The token endpoint does the rest: it refuses a different `resource` at redemption, stamps
`aud`, and binds any refresh token to the same audience.

## 4. What the MCP client sees

1. `POST https://acme.example/mcp` → `401`, `WWW-Authenticate: Bearer resource_metadata="https://acme.example/.well-known/oauth-protected-resource/mcp", error="invalid_token"`.
2. It reads that document, then `/.well-known/oauth-authorization-server` from the listed
   authorization server.
3. It registers at `registration_endpoint` (`token_endpoint_auth_method: none`, its loopback
   or https callback) — or, when `client_id_metadata_document_supported` is `true`, uses
   its document URL as `client_id` and skips registration.
4. It opens `/oauth/authorize?…&code_challenge=…&resource=https://acme.example/mcp`.
5. It redeems the code at `/oauth/token` with the same `resource`, and gets a token whose
   `aud` is `https://acme.example/mcp`.
6. It refreshes with `refresh_token` (and the same `resource`, or none) until the grant ends.

## 5. Test it

```php
it('serves MCP to a client with a metadata document', function (): void {
    $this->declareProtectedResource('/mcp', ['mcp:read']);

    $this->fakeClientMetadataDocuments()->serve('https://client.example/meta.json', [
        'client_id' => 'https://client.example/meta.json',
        'client_name' => 'Example',
        'redirect_uris' => ['http://127.0.0.1:33418/callback'],
    ]);

    $client = app(AuthorizationClients::class)->resolve('https://client.example/meta.json');

    expect($client->documentHost)->toBe('client.example');
});
```

`fakeClientMetadataDocuments()` answers every document fetch from memory; `->refuseAsUnsafe($url)`
makes one fail the way the SSRF guard refuses a private address.

## Limits

- **One resource per token.** RFC 8707 allows several; this server refuses a repeated
  `resource` with `invalid_target`, because a token valid at two resource servers can be
  replayed by either at the other. A client that needs two asks twice.
- **A refresh token never changes audience.** Naming a different `resource` on refresh is
  `invalid_target`, and the refresh token survives the refusal.
- **Metadata documents are a draft.** The validation follows
  draft-ietf-oauth-client-id-metadata-document; details may move before it is an RFC.
  Inline `jwks` in a document is refused — publish keys at `jwks_uri`.
- The package does not serve `/authorize` or the MCP endpoint; both are yours, as above.
