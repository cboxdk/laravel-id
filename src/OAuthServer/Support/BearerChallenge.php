<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

use Cbox\Id\OAuthServer\ValueObjects\AuthenticationRequirement;
use Cbox\Id\OAuthServer\ValueObjects\ProtectedResource;
use InvalidArgumentException;

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
 *
 * STEP-UP (RFC 9470). A token can be live, audienced and scoped correctly and still come
 * from an authentication the resource will not act on — a password-only login in front of
 * a payment, or one from yesterday in front of an account deletion. The resource answers
 * 401 with `error="insufficient_user_authentication"` and says what it needs: `acr_values`
 * (the classes it accepts) and/or `max_age` (how recent the login must be). The client
 * re-runs `/authorize` with those two parameters and comes back with a token that meets
 * them. {@see insufficientUserAuthentication()} builds that challenge;
 * {@see AuthenticationRequirement::challenge()} builds it from the requirement that failed.
 */
readonly class BearerChallenge
{
    /** RFC 9470 §3: the token's authentication event does not meet the resource's requirements. */
    public const INSUFFICIENT_USER_AUTHENTICATION = 'insufficient_user_authentication';

    /**
     * @param  list<string>  $scopes  RFC 6750 §3 `scope`: what a token would need to be accepted
     * @param  list<string>  $acrValues  RFC 9470 §3 `acr_values`: the authentication context
     *                                   classes the resource accepts, in order of preference
     * @param  int|null  $maxAge  RFC 9470 §3 `max_age`: the allowable elapsed time, in seconds,
     *                            since the user last actively authenticated
     *
     * @throws InvalidArgumentException for a negative `max_age` or an `acr_values` entry
     *                                  containing whitespace (it would split into two values)
     */
    public function __construct(
        public ?string $resourceMetadata = null,
        public ?string $error = null,
        public ?string $errorDescription = null,
        public array $scopes = [],
        public ?string $realm = null,
        /** `Bearer`, or `DPoP` (RFC 9449 §7.1) for a resource that expects proof of possession. */
        public string $scheme = 'Bearer',
        public array $acrValues = [],
        public ?int $maxAge = null,
    ) {
        if ($maxAge !== null && $maxAge < 0) {
            throw new InvalidArgumentException('max_age must be a non-negative integer (RFC 9470 §3).');
        }

        foreach ($acrValues as $value) {
            // The parameter is a space-separated list, so a value holding whitespace would
            // be read back as two classes the resource never named.
            if ($value === '' || preg_match('/\s/', $value) === 1) {
                throw new InvalidArgumentException('An acr_values entry must be a non-empty string without whitespace.');
            }
        }
    }

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
        return new self($this->resourceMetadata, $error, $description, $this->scopes, $this->realm, $this->scheme, $this->acrValues, $this->maxAge);
    }

    /**
     * @param  list<string>  $scopes
     */
    public function withScopes(array $scopes): self
    {
        return new self($this->resourceMetadata, $this->error, $this->errorDescription, $scopes, $this->realm, $this->scheme, $this->acrValues, $this->maxAge);
    }

    public function withScheme(string $scheme): self
    {
        return new self($this->resourceMetadata, $this->error, $this->errorDescription, $this->scopes, $this->realm, $scheme, $this->acrValues, $this->maxAge);
    }

    /**
     * @param  list<string>  $acrValues  RFC 9470 §3 `acr_values`, in order of preference
     */
    public function withAcrValues(array $acrValues): self
    {
        return new self($this->resourceMetadata, $this->error, $this->errorDescription, $this->scopes, $this->realm, $this->scheme, $acrValues, $this->maxAge);
    }

    /** RFC 9470 §3 `max_age`, in seconds; null removes it. */
    public function withMaxAge(?int $maxAge): self
    {
        return new self($this->resourceMetadata, $this->error, $this->errorDescription, $this->scopes, $this->realm, $this->scheme, $this->acrValues, $maxAge);
    }

    /**
     * The RFC 9470 §3 step-up challenge: `error="insufficient_user_authentication"` plus
     * what the resource needs. Send it with status 401, as the RFC's examples do — the
     * token was fine as a token; it is the login behind it that falls short, and 401 is
     * what makes a client go back to the authorization server.
     *
     * Keeps `resource_metadata`, `realm`, the scheme and any `scope` already set, so it
     * composes with {@see for()}: `BearerChallenge::for($resource)->insufficientUserAuthentication(…)`.
     *
     * @param  list<string>  $acrValues
     */
    public function insufficientUserAuthentication(array $acrValues = [], ?int $maxAge = null, ?string $description = null): self
    {
        return new self(
            $this->resourceMetadata,
            self::INSUFFICIENT_USER_AUTHENTICATION,
            $description,
            $this->scopes,
            $this->realm,
            $this->scheme,
            $acrValues,
            $maxAge,
        );
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
            'acr_values' => $this->acrValues === [] ? null : implode(' ', $this->acrValues),
            // Quoted like every other value: RFC 9470 §3 allows a token or a quoted-string,
            // and its own example is `max_age="5"`.
            'max_age' => $this->maxAge === null ? null : (string) $this->maxAge,
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
