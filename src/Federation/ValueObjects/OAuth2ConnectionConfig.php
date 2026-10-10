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
    /**
     * @param  list<string>  $scopes  ADDITIONAL scopes the administrator asked for, requested
     *                                on top of the catalogue's own — which sign-in needs and
     *                                which can therefore never be taken away here
     */
    public function __construct(
        public string $provider,
        public string $clientId,
        public string $clientSecret,
        public array $scopes = [],
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
            scopes: self::scopes($config),
        );
    }

    /**
     * The extra scopes, as a clean list: strings only, trimmed, without blanks or repeats.
     *
     * @param  array<string, mixed>  $config
     * @return list<string>
     */
    private static function scopes(array $config): array
    {
        $scopes = [];

        foreach (is_array($config['scopes'] ?? null) ? $config['scopes'] : [] as $scope) {
            if (is_string($scope) && trim($scope) !== '') {
                $scopes[] = trim($scope);
            }
        }

        return array_values(array_unique($scopes));
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
