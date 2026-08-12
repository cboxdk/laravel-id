<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\ValueObjects;

use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;

/**
 * An OIDC connection's relying-party configuration, parsed once from the sealed blob.
 *
 * This was an `array<string, mixed>` threaded through ten private helpers in the
 * assertion validator and three more in the client, each re-reading string keys and
 * re-validating the same shape — so adding `jwks_uri` meant finding every reader. It
 * is durable, admin-authored configuration, not an HTTP body: the only array is the
 * JSON at rest, parsed here on the way out of
 * {@see SecretBox} and serialized back only on the
 * way in.
 *
 * Required: `issuer`, `client_id`. Verification material is one of `jwks_uri` (the
 * IdP's live JWKS — preferred, because a signing-key rotation is picked up
 * automatically), `signing_keys` (kid → PEM) or `signing_key` (a single PEM, for an
 * IdP that omits `kid`). Having NONE of the three is only an error at verification
 * time, not at parse time, so a connection can be drafted before its keys are known.
 */
readonly class OidcConnectionConfig
{
    /**
     * @param  array<string, string>  $signingKeys  kid → PEM public key
     * @param  list<string>  $scopes  empty means the default `openid email profile`
     */
    public function __construct(
        public string $issuer,
        public string $clientId,
        public ?string $clientSecret = null,
        public ?string $authorizationEndpoint = null,
        public ?string $tokenEndpoint = null,
        public ?string $jwksUri = null,
        public array $signingKeys = [],
        public ?string $signingKey = null,
        public array $scopes = [],

        /**
         * Set when the provider issues no secret to paste and expects a signed assertion
         * minted per request instead — see {@see SigningKeyCredential}. Mutually exclusive
         * with `$clientSecret` in practice; the client prefers this one when both exist,
         * because a provider that mints cannot also accept a pasted string.
         */
        public ?SigningKeyCredential $signingCredential = null,
    ) {}

    /**
     * @param  array<string, mixed>  $config  the unsealed JSON
     */
    public static function fromArray(array $config): self
    {
        return new self(
            issuer: self::require($config, 'issuer'),
            clientId: self::require($config, 'client_id'),
            clientSecret: self::optional($config, 'client_secret'),
            authorizationEndpoint: self::optional($config, 'authorization_endpoint'),
            tokenEndpoint: self::optional($config, 'token_endpoint'),
            jwksUri: self::optional($config, 'jwks_uri'),
            signingKeys: self::stringMap($config, 'signing_keys'),
            signingKey: self::optional($config, 'signing_key'),
            scopes: self::stringList($config, 'scopes'),
            signingCredential: SigningKeyCredential::fromArray($config),
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return array_filter([
            'issuer' => $this->issuer,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'authorization_endpoint' => $this->authorizationEndpoint,
            'token_endpoint' => $this->tokenEndpoint,
            'jwks_uri' => $this->jwksUri,
            'signing_keys' => $this->signingKeys,
            'signing_key' => $this->signingKey,
            'scopes' => $this->scopes,
            ...($this->signingCredential?->toArray() ?? []),
        ], static fn (mixed $value): bool => $value !== null && $value !== []);
    }

    /** The scope string for an authorization request. */
    public function scopeString(): string
    {
        return $this->scopes === [] ? 'openid email profile' : implode(' ', $this->scopes);
    }

    /**
     * A field the flow cannot proceed without, asserted at the POINT OF USE rather
     * than at parse time: the endpoints and the client secret are needed only by the
     * client (authorize + code exchange), never by the assertion validator, so a
     * connection is not forced to carry them to be readable.
     */
    public function requireField(?string $value, string $key): string
    {
        if ($value === null) {
            throw InvalidAssertion::make("connection config missing [{$key}]");
        }

        return $value;
    }

    /**
     * @param  array<string, mixed>  $config
     */
    private static function require(array $config, string $key): string
    {
        $value = $config[$key] ?? null;

        if (! is_string($value) || $value === '') {
            throw InvalidAssertion::make("connection config missing [{$key}]");
        }

        return $value;
    }

    /**
     * @param  array<string, mixed>  $config
     */
    private static function optional(array $config, string $key): ?string
    {
        $value = $config[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @param  array<string, mixed>  $config
     * @return array<string, string>
     */
    private static function stringMap(array $config, string $key): array
    {
        $value = $config[$key] ?? null;

        if (! is_array($value)) {
            return [];
        }

        $map = [];
        foreach ($value as $mapKey => $item) {
            if (is_string($item) && $item !== '') {
                $map[(string) $mapKey] = $item;
            }
        }

        return $map;
    }

    /**
     * @param  array<string, mixed>  $config
     * @return list<string>
     */
    private static function stringList(array $config, string $key): array
    {
        $value = $config[$key] ?? null;

        if (! is_array($value)) {
            return [];
        }

        return array_values(array_filter(
            $value,
            static fn (mixed $item): bool => is_string($item) && $item !== '',
        ));
    }
}
