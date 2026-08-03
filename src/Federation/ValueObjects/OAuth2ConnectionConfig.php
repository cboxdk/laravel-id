<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\ValueObjects;

use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\ProviderCatalog;

/**
 * A tenant's credentials for a plain OAuth 2.0 provider, resolved against the catalogue.
 *
 * The split is deliberate: the tenant supplies the client id and secret, and everything
 * else — endpoints, scopes, where the identity sits in the response — comes from the
 * catalogue entry named by `provider`. An administrator who could also type the endpoints
 * would be able to point a "GitHub" connection at a host of their choosing, and the
 * button on the login page would still say GitHub.
 */
readonly class OAuth2ConnectionConfig
{
    public function __construct(
        public string $provider,
        public string $clientId,
        public string $clientSecret,
    ) {}

    /**
     * @param  array<string, mixed>  $config  the unsealed JSON
     */
    public static function fromArray(array $config): self
    {
        $provider = self::require($config, 'provider');

        if (ProviderCatalog::find($provider)?->isOidc() !== false) {
            // Either the key names nothing, or it names an OIDC provider that must not be
            // driven through this path — no id_token would ever be verified.
            throw InvalidAssertion::make('connection names no OAuth 2.0 provider: '.$provider);
        }

        return new self(
            provider: $provider,
            clientId: self::require($config, 'client_id'),
            clientSecret: self::require($config, 'client_secret'),
        );
    }

    /**
     * @param  array<string, mixed>  $config
     */
    private static function require(array $config, string $key): string
    {
        $value = $config[$key] ?? null;

        if (! is_string($value) || trim($value) === '') {
            throw InvalidAssertion::make('connection is missing '.$key);
        }

        return trim($value);
    }
}
