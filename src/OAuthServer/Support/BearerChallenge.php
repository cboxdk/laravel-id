<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

use Cbox\Id\OAuthServer\ValueObjects\ProtectedResource;

/**
 * An RFC 6750 §3 `WWW-Authenticate` challenge, with RFC 9728 §5.1's `resource_metadata`.
 *
 * A resource server answers a request without a usable token with 401 and this header.
 * `resource_metadata` is the URL of the resource's protected resource metadata, which is
 * how a client that knows nothing but the resource's URL — an MCP client pointed at
 * `https://host/mcp` — finds the authorization server, the scopes and everything else.
 * Without it the client has to guess the well-known URL; with it there is nothing to
 * guess. A host protecting its own endpoint builds the challenge from the declared
 * {@see ProtectedResource}: `BearerChallenge::for($resource)->withError('invalid_token')`.
 *
 * Every parameter value is a quoted-string (RFC 9110 §11.2), escaped, so an
 * `error_description` carrying a quote cannot end the header early or smuggle a parameter.
 * The zero-argument form is valid: a bare `Bearer` challenge.
 */
readonly class BearerChallenge
{
    /**
     * @param  list<string>  $scopes  RFC 6750 §3 `scope`: what a token would need to be accepted
     */
    public function __construct(
        public ?string $resourceMetadata = null,
        public ?string $error = null,
        public ?string $errorDescription = null,
        public array $scopes = [],
        public ?string $realm = null,
        /** `Bearer`, or `DPoP` (RFC 9449 §7.1) for a resource that expects proof of possession. */
        public string $scheme = 'Bearer',
    ) {}

    public static function for(ProtectedResource $resource): self
    {
        return new self(resourceMetadata: $resource->metadataUrl());
    }

    /**
     * RFC 6750 §3.1: `invalid_request` (400), `invalid_token` (401) or
     * `insufficient_scope` (403). The status is the caller's; the code goes here.
     */
    public function withError(string $error, ?string $description = null): self
    {
        return new self($this->resourceMetadata, $error, $description, $this->scopes, $this->realm, $this->scheme);
    }

    /**
     * @param  list<string>  $scopes
     */
    public function withScopes(array $scopes): self
    {
        return new self($this->resourceMetadata, $this->error, $this->errorDescription, $scopes, $this->realm, $this->scheme);
    }

    public function withScheme(string $scheme): self
    {
        return new self($this->resourceMetadata, $this->error, $this->errorDescription, $this->scopes, $this->realm, $scheme);
    }

    /**
     * The header value, e.g.
     * `Bearer resource_metadata="https://h/.well-known/oauth-protected-resource/mcp", error="invalid_token"`.
     */
    public function header(): string
    {
        $params = [];

        foreach ([
            'realm' => $this->realm,
            'resource_metadata' => $this->resourceMetadata,
            'error' => $this->error,
            'error_description' => $this->errorDescription,
            'scope' => $this->scopes === [] ? null : implode(' ', $this->scopes),
        ] as $name => $value) {
            if ($value !== null && $value !== '') {
                $params[] = $name.'="'.self::quote($value).'"';
            }
        }

        return $params === [] ? $this->scheme : $this->scheme.' '.implode(', ', $params);
    }

    /**
     * @return array{WWW-Authenticate: string}
     */
    public function headers(): array
    {
        return ['WWW-Authenticate' => $this->header()];
    }

    private static function quote(string $value): string
    {
        // Control characters have no business in a header; quotes and backslashes are
        // escaped as RFC 9110 §5.6.4 quoted-pairs.
        $value = (string) preg_replace('/[\x00-\x1F\x7F]/', ' ', $value);

        return addcslashes($value, '"\\');
    }
}
