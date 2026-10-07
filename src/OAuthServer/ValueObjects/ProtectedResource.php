<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Contracts\ProtectedResources;
use Cbox\Id\OAuthServer\Enums\ProtocolScope;
use Cbox\Id\OAuthServer\Exceptions\InvalidProtectedResource;

/**
 * A resource server this environment issues tokens for that is NOT a registered API: one
 * the host application serves itself and declares in code — an MCP endpoint at
 * `https://{host}/mcp`, say — through {@see ProtectedResources}.
 *
 * WHY NOT AN API ROW. A registered API is data an operator manages per environment, with
 * an owner and a lifecycle. A host's own endpoint is part of the host's code: it exists in
 * every environment the host serves, its scopes ship with the release that handles them,
 * and nobody should be able to delete it from a console. Declaring it is the same fact as
 * routing it.
 *
 * THE IDENTIFIER IS THE AUDIENCE. It is the RFC 8707 `resource` a client asks for, the
 * `aud` the token carries, and the RFC 9728 `resource` the metadata document names — one
 * string, compared exactly, so the three cannot disagree. Validated when constructed:
 * https (http only on a loopback host, for development), no query, no fragment, no
 * credentials. A query or fragment would make the RFC 9728 well-known URL ambiguous.
 *
 * Constructing it with only an identifier is valid and meaningful: a resource that accepts
 * no scopes beyond the protocol ones, closed to self-registered clients.
 */
readonly class ProtectedResource
{
    /** RFC 9728 §3: the well-known URI suffix protected resource metadata lives under. */
    public const WELL_KNOWN = '/.well-known/oauth-protected-resource';

    /** RFC 6749 §3.3 scope-token, the same rule an API's scopes are held to. */
    private const SCOPE_TOKEN = '/^[\x21\x23-\x5B\x5D-\x7E]{1,128}$/';

    /**
     * @param  list<string>  $scopes  the scopes this resource accepts, beyond the protocol scopes every token may carry
     */
    public function __construct(
        public string $identifier,
        public array $scopes = [],
        /**
         * Whether a self-registered client — RFC 7591 registration, or a client ID
         * metadata document — may be issued a token for this resource. Off unless the
         * host says so: a self-registered client is whoever reached the registration
         * endpoint, and opening a resource to them is a decision, not a default.
         */
        public bool $dynamicClients = false,
        /** RFC 9728 `resource_name`: what a consent screen may call it. */
        public ?string $name = null,
        /** RFC 9728 `resource_documentation`: a human-readable page about it. */
        public ?string $documentation = null,
        /**
         * The app whose declared roles/permissions a token for this resource carries;
         * null = the requesting client's own, as for any unregistered audience.
         */
        public ?string $clientId = null,
    ) {
        if (! self::isServableIdentifier($identifier)) {
            throw InvalidProtectedResource::identifier($identifier);
        }

        foreach ($scopes as $scope) {
            if (preg_match(self::SCOPE_TOKEN, $scope) !== 1) {
                throw InvalidProtectedResource::scope($scope);
            }

            // The protocol scopes belong to the issuer and ride on every token already;
            // a resource "owning" `openid` would read as narrowing it, which it cannot.
            if (ProtocolScope::isProtocol($scope)) {
                throw InvalidProtectedResource::protocolScope($scope);
            }
        }
    }

    public function accepts(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    /**
     * RFC 9728 §3.1: the metadata URL is the identifier with the well-known suffix
     * INSERTED between the host and the path — `https://h/mcp` is described at
     * `https://h/.well-known/oauth-protected-resource/mcp`, not at a suffix of the path.
     * That is what lets one host describe several resources, and what an MCP client
     * builds from the URL it was given.
     */
    public function metadataUrl(): string
    {
        $parts = parse_url($this->identifier);
        $scheme = is_array($parts) && isset($parts['scheme']) ? $parts['scheme'] : 'https';
        $host = is_array($parts) && isset($parts['host']) ? $parts['host'] : '';
        $port = is_array($parts) && isset($parts['port']) ? ':'.$parts['port'] : '';

        return $scheme.'://'.$host.$port.$this->metadataPath();
    }

    /**
     * The path half of {@see metadataUrl()}, which is what a route matches on.
     */
    public function metadataPath(): string
    {
        $path = parse_url($this->identifier, PHP_URL_PATH);
        $path = is_string($path) ? rtrim($path, '/') : '';

        return self::WELL_KNOWN.$path;
    }

    /**
     * The RFC 9728 §2 document for this resource. A serialization edge — the shape is the
     * wire format, so it is built here and nowhere else.
     *
     * @return array<string, mixed>
     */
    public function metadata(string $issuer): array
    {
        $document = [
            'resource' => $this->identifier,
            'authorization_servers' => [$issuer],
            // Advertised as the scopes a token for THIS resource can carry: the protocol
            // ones ride on every token, so a client reading only this document can still
            // ask for a refresh token.
            'scopes_supported' => array_values(array_unique([...$this->scopes, ProtocolScope::OfflineAccess->value])),
            // RFC 6750 §2.1 only. Form-body and query tokens leak into logs and caches,
            // and nothing this package helps a resource server read accepts them.
            'bearer_methods_supported' => ['header'],
        ];

        if ($this->name !== null && $this->name !== '') {
            $document['resource_name'] = $this->name;
        }

        if ($this->documentation !== null && $this->documentation !== '') {
            $document['resource_documentation'] = $this->documentation;
        }

        return $document;
    }

    /**
     * A resource identifier this package will serve metadata for and stamp into `aud`.
     */
    public static function isServableIdentifier(string $identifier): bool
    {
        if ($identifier === '' || strlen($identifier) > 255 || trim($identifier) !== $identifier) {
            return false;
        }

        $parts = parse_url($identifier);

        if (! is_array($parts) || ! isset($parts['scheme'], $parts['host'])
            || isset($parts['query']) || isset($parts['fragment']) || isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }

        $scheme = strtolower($parts['scheme']);

        if ($scheme === 'https') {
            return true;
        }

        return $scheme === 'http' && in_array(strtolower($parts['host']), ['localhost', '127.0.0.1', '[::1]'], true);
    }
}
