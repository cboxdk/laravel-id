<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Api\Support\ClientAuthenticator;
use Cbox\Id\Api\Support\ServerMetadata;
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\DynamicClientRegistration;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadata;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\ClientMetadata;
use Cbox\Id\OAuthServer\ValueObjects\ClientSecret;
use Cbox\Id\OAuthServer\ValueObjects\DynamicRegistration;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Id\OAuthServer\ValueObjects\UpdatedRegistration;

/**
 * RFC 7591 / 7592 implementation. Validation is deliberately strict and
 * secure-by-default: unknown grant types are rejected, requested scopes are
 * reduced to the configured allow-list, and redirect URIs must be well-formed
 * and non-fragment (loopback http is permitted for native/CLI clients, which is
 * exactly the MCP case).
 */
class DynamicClientRegistrar implements DynamicClientRegistration
{
    // Lazy per-call resolution of the ambient environment. This class is a `singleton`
    // (OAuthServerServiceProvider) and EnvironmentContext is `scoped`, so injecting it here
    // would pin a queue worker to the first job's environment for the life of the process.
    use ResolvesEnvironment;

    /**
     * The methods a client may register with — and this list has to agree with
     * `token_endpoint_auth_methods_supported` in {@see ServerMetadata}.
     *
     * `private_key_jwt` was missing while discovery advertised it in three places (token,
     * revocation, introspection). The token endpoint has always accepted it
     * ({@see ClientAuthenticator}) and the registry has always stored
     * a JWK Set instead of issuing a secret — only this door refused, with `unsupported
     * token_endpoint_auth_method`. A conformant client read the metadata, asked for the
     * strongest method the server claimed, and was turned away from a capability that was
     * fully built behind it. Advertised-but-unfulfilled, pointing the unusual way round.
     */
    private const AUTH_METHODS = ['none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt'];

    public function __construct(
        private readonly ClientRegistry $clients,
    ) {}

    public function validate(array $request): ClientMetadata
    {
        $authMethod = $this->authMethod($request);
        $grantTypes = $this->grantTypes($request);
        $responseTypes = $this->responseTypes($request, $grantTypes);
        $redirectUris = $this->redirectUris($request, $grantTypes);

        // A client that authenticates with a secret cannot be public, and a
        // public client cannot use client_credentials (it has no secret to prove).
        if ($authMethod === 'none' && in_array('client_credentials', $grantTypes, true)) {
            throw InvalidClientMetadata::metadata('client_credentials requires a confidential client (token_endpoint_auth_method must not be "none")');
        }

        return new ClientMetadata(
            clientName: $this->clientName($request),
            tokenEndpointAuthMethod: $authMethod,
            redirectUris: $redirectUris,
            grantTypes: $grantTypes,
            responseTypes: $responseTypes,
            scopes: $this->scopes($request),
            jwks: $this->jwks($request, $authMethod),
        );
    }

    public function register(ClientMetadata $metadata): DynamicRegistration
    {
        $registered = $this->clients->register(new NewClient(
            name: $metadata->clientName,
            type: $metadata->isPublic() ? ClientType::Public : ClientType::Confidential,
            redirectUris: $metadata->redirectUris,
            grantTypes: $metadata->grantTypes,
            scopes: $metadata->scopes,
            // The registry issues NO secret when a key set arrives — one credential
            // mechanism, not two — so this is what makes a private_key_jwt registration
            // produce a client that can actually authenticate rather than one with
            // neither credential.
            jwks: $metadata->jwks,
        ));

        $registrationToken = 'reg_'.bin2hex(random_bytes(32));

        $registered->client->forceFill([
            // THE CHOICE, WRITTEN DOWN. Inferring it back from the row cannot tell
            // `client_secret_post` from `client_secret_basic` — both are "has a secret" —
            // so a client that registered the former was handed a management document
            // telling it to use the latter.
            'token_endpoint_auth_method' => $metadata->tokenEndpointAuthMethod(),
            'registration_access_token_hash' => hash('sha256', $registrationToken),
        ])->save();

        return new DynamicRegistration($registered->client, $registered->secret, $registrationToken);
    }

    public function authenticate(string $clientId, string $registrationAccessToken): ?Client
    {
        $client = $this->clients->byClientId($clientId);
        $hasToken = $client !== null && $client->registration_access_token_hash !== null;

        // Compare against a fixed dummy when the client or its token hash is
        // absent, so a caller can't distinguish "no such client" from "wrong
        // token" by timing.
        $stored = $hasToken ? $client->registration_access_token_hash : hash('sha256', 'absent');
        $matches = hash_equals($stored, hash('sha256', $registrationAccessToken));

        return $matches && $hasToken ? $client : null;
    }

    public function update(Client $client, ClientMetadata $metadata): UpdatedRegistration
    {
        // A CLIENT THAT ARRIVES AT A SECRET METHOD MUST LEAVE WITH A SECRET.
        //
        // The comment below has described this since the downgrade fix: "an update back to
        // `client_secret_basic` should mint a fresh one rather than silently resurrect the
        // old". It described an intention. A client that had moved to `private_key_jwt`
        // had its hash cleared, so moving BACK left `usesASharedSecret()` true and
        // `secret_hash` null — a client registered for Basic with no password, unable to
        // authenticate, and nothing in the response saying why.
        $minted = null;

        if ($metadata->usesASharedSecret() && $client->secret_hash === null) {
            $minted = ClientSecret::mint();
        }

        $client->forceFill([
            'name' => $metadata->clientName,
            'type' => $metadata->isPublic() ? ClientType::Public : ClientType::Confidential,
            'redirect_uris' => $metadata->redirectUris,
            'grant_types' => $metadata->grantTypes,
            'scopes' => $metadata->scopes,
            // RFC 7592 §2.2: an update REPLACES the metadata, so keys omitted from the
            // new document are gone. Leaving the old set in place would mean a client
            // could never rotate away from a compromised key through the API it was told
            // to manage itself with.
            'jwks' => $metadata->jwks,
            // AND THE SECRET GOES WITH THE METHOD. A client that updates itself to `none`
            // or to `private_key_jwt` no longer authenticates with a shared secret, and
            // leaving the hash on the row kept a credential alive that the client's own
            // registered metadata says is not in use.
            //
            // `ClientAuthenticator` already refuses to LOG IN with it — the disjunction
            // there treats "secret still on file" as proof the client is confidential,
            // which is what closes the downgrade bypass. This is the other half: the row
            // should not carry a live credential the client believes it has retired, and
            // an update back to `client_secret_basic` should mint a fresh one rather than
            // silently resurrect the old.
            'secret_hash' => $minted !== null
                ? $minted->hash
                : ($metadata->usesASharedSecret() ? $client->secret_hash : null),
            'token_endpoint_auth_method' => $metadata->tokenEndpointAuthMethod(),
        ])->save();

        return new UpdatedRegistration($client, $minted?->plaintext);
    }

    public function delete(Client $client): void
    {
        $client->delete();
    }

    /**
     * @param  array<string, mixed>  $request
     */
    private function clientName(array $request): string
    {
        $name = $request['client_name'] ?? null;

        return is_string($name) && trim($name) !== '' ? trim($name) : 'Dynamic client';
    }

    /**
     * @param  array<string, mixed>  $request
     */
    private function authMethod(array $request): string
    {
        // RFC 7591 §2: the default when omitted is client_secret_basic.
        $method = $request['token_endpoint_auth_method'] ?? 'client_secret_basic';

        if (! is_string($method) || ! in_array($method, self::AUTH_METHODS, true)) {
            throw InvalidClientMetadata::metadata('unsupported token_endpoint_auth_method');
        }

        return $method;
    }

    /**
     * The client's public JWK Set, required by and only meaningful for `private_key_jwt`.
     *
     * RFC 7591 §2 defines both `jwks` and `jwks_uri`, and this accepts the inline one
     * ONLY. `jwks_uri` means the server fetches a URL the registrant chose, on a schedule
     * the registrant influences, from an endpoint that is unauthenticated in `open` mode —
     * a server-side request forgery primitive handed out by a public API. It is refused
     * OUT LOUD rather than dropped: silently ignoring it would register a client whose
     * keys the server never reads, and the first thing that client learns is that every
     * assertion it signs is rejected, with nothing anywhere saying why. That is the same
     * defect as advertising a method and refusing it, one layer in.
     *
     * @param  array<string, mixed>  $request
     * @return array<string, mixed>|null
     */
    private function jwks(array $request, string $authMethod): ?array
    {
        $jwks = $request['jwks'] ?? null;

        if (isset($request['jwks_uri'])) {
            throw InvalidClientMetadata::metadata('jwks_uri is not supported here — register the key set inline as "jwks"');
        }

        if ($authMethod !== 'private_key_jwt') {
            // Keys on a client that authenticates some other way would be stored and never
            // consulted. Refusing says which of the two the registrant got wrong.
            if ($jwks !== null) {
                throw InvalidClientMetadata::metadata('jwks is only accepted with token_endpoint_auth_method "private_key_jwt"');
            }

            return null;
        }

        // A private_key_jwt client with no keys can never authenticate — the registry
        // issues it no secret either, so registering one mints a credential-less client
        // that 401s forever.
        if (! is_array($jwks) || ! isset($jwks['keys']) || ! is_array($jwks['keys']) || $jwks['keys'] === []) {
            throw InvalidClientMetadata::metadata('token_endpoint_auth_method "private_key_jwt" requires a non-empty "jwks" key set');
        }

        /** @var array<string, mixed> $jwks */
        return $jwks;
    }

    /**
     * @param  array<string, mixed>  $request
     * @return list<string>
     */
    private function grantTypes(array $request): array
    {
        $requested = $this->stringList($request['grant_types'] ?? null);
        $requested = $requested === [] ? ['authorization_code'] : $requested;

        $allowed = $this->configList('allowed_grant_types');

        foreach ($requested as $grant) {
            if (! in_array($grant, $allowed, true)) {
                throw InvalidClientMetadata::metadata("grant_type not permitted: {$grant}");
            }
        }

        return array_values(array_unique($requested));
    }

    /**
     * @param  array<string, mixed>  $request
     * @param  list<string>  $grantTypes
     * @return list<string>
     */
    private function responseTypes(array $request, array $grantTypes): array
    {
        $requested = $this->stringList($request['response_types'] ?? null);
        $requested = $requested === [] ? [] : $requested;

        foreach ($requested as $type) {
            if ($type !== 'code') {
                throw InvalidClientMetadata::metadata("response_type not supported: {$type}");
            }
        }

        // The authorization_code grant implies the "code" response type.
        if (in_array('authorization_code', $grantTypes, true)) {
            return ['code'];
        }

        return $requested;
    }

    /**
     * @param  array<string, mixed>  $request
     * @param  list<string>  $grantTypes
     * @return list<string>
     */
    private function redirectUris(array $request, array $grantTypes): array
    {
        $uris = $this->stringList($request['redirect_uris'] ?? null);
        $needsRedirect = in_array('authorization_code', $grantTypes, true);

        if ($needsRedirect && $uris === []) {
            throw InvalidClientMetadata::redirectUri('redirect_uris is required for the authorization_code grant');
        }

        foreach ($uris as $uri) {
            $this->assertRedirectUri($uri);
        }

        return $uris;
    }

    private function assertRedirectUri(string $uri): void
    {
        $parts = parse_url($uri);

        if ($parts === false || ! isset($parts['scheme'])) {
            throw InvalidClientMetadata::redirectUri("redirect_uri is not an absolute URI: {$uri}");
        }

        // A fragment in a redirect URI is forbidden (RFC 6749 §3.1.2).
        if (isset($parts['fragment'])) {
            throw InvalidClientMetadata::redirectUri("redirect_uri must not contain a fragment: {$uri}");
        }

        $scheme = strtolower($parts['scheme']);

        // A private-use ("custom") URI scheme is allowed for native apps
        // (RFC 8252 §7.1), in both the authority form (com.example.app://cb) and
        // the canonical path form (com.example.app:/cb) — the latter has no host,
        // so it is handled before the http(s) host requirement below.
        //
        // RFC 8252 §7.1 requires the scheme to be a domain name the app controls in
        // reverse order (com.example.app), which always contains a dot. Enforcing that
        // both follows the spec and refuses the dangerous single-word schemes a renderer
        // may execute — javascript:, data:, vbscript:, file:, blob: — which would
        // otherwise be stored and become XSS in the AS origin if the host app ever
        // rendered a redirect_uri as a link.
        if ($scheme !== 'http' && $scheme !== 'https') {
            if (! str_contains($scheme, '.')) {
                throw InvalidClientMetadata::redirectUri("redirect_uri custom scheme must be a reverse-domain name (e.g. com.example.app): {$uri}");
            }

            return;
        }

        // http(s) reserved schemes must carry a host: https everywhere, plain http
        // only for loopback (native/CLI/MCP clients, RFC 8252 §7.3).
        $host = isset($parts['host']) ? strtolower($parts['host']) : null;
        $isLoopback = in_array($host, ['localhost', '127.0.0.1', '::1'], true);

        if ($scheme === 'https' && $host !== null) {
            return;
        }

        if ($scheme === 'http' && $isLoopback) {
            return;
        }

        // A sandbox environment is for development, so it accepts plain http on any
        // host (e.g. http://app.test) — never permitted in production.
        if ($scheme === 'http' && $host !== null && ($this->environments()->current()?->isSandbox() ?? false)) {
            return;
        }

        throw InvalidClientMetadata::redirectUri("redirect_uri must use https (or http on loopback): {$uri}");
    }

    /**
     * @param  array<string, mixed>  $request
     * @return list<string>
     */
    private function scopes(array $request): array
    {
        $raw = $request['scope'] ?? '';
        $requested = is_string($raw)
            ? array_values(array_filter(explode(' ', $raw), static fn (string $s): bool => $s !== ''))
            : [];

        $allowed = $this->configList('allowed_scopes');

        // RFC 7591 §2: the server MAY reduce the requested scopes. Silently drop
        // any outside the allow-list rather than failing the whole registration.
        return array_values(array_filter($requested, static fn (string $s): bool => in_array($s, $allowed, true)));
    }

    /**
     * @return list<string>
     */
    private function stringList(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        return array_values(array_filter($value, static fn (mixed $v): bool => is_string($v) && $v !== ''));
    }

    /**
     * @return list<string>
     */
    private function configList(string $key): array
    {
        $value = config("cbox-id.oauth.dynamic_registration.{$key}");

        return is_array($value) ? array_values(array_filter($value, 'is_string')) : [];
    }
}
