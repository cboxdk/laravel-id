<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Enums\GrantType;
use Cbox\Id\OAuthServer\Enums\TokenEndpointAuthMethod;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadata;

/**
 * The rules a client's settings must satisfy however they arrive — the registry's
 * register and update, a blueprint import, and RFC 7591 registration. One place, so the
 * console and the self-registration door cannot drift apart on what a client may be.
 */
class ClientSettingsRules
{
    /**
     * Every grant must be one the token endpoint implements, and a grant only a
     * confidential client may use must not be given to a public one.
     *
     * @param  list<string>  $grantTypes
     *
     * @throws InvalidClientMetadata
     */
    public static function assertGrants(array $grantTypes, ClientType $type): void
    {
        foreach ($grantTypes as $grant) {
            $known = GrantType::tryFrom($grant);

            if ($known === null) {
                throw InvalidClientMetadata::metadata("grant_type not supported: {$grant}");
            }

            if ($known->requiresConfidentialClient() && $type !== ClientType::Confidential) {
                throw InvalidClientMetadata::metadata("grant_type {$grant} requires a confidential client");
            }
        }
    }

    /**
     * The registered authentication method must agree with the client type and with the
     * credential the client will hold. Null (inferred from the type) is always accepted.
     *
     * @param  array<string, mixed>|null  $jwks
     *
     * @throws InvalidClientMetadata
     */
    public static function assertAuthMethod(?TokenEndpointAuthMethod $method, ClientType $type, ?array $jwks): void
    {
        if ($method === null) {
            return;
        }

        if (($method === TokenEndpointAuthMethod::None) !== ($type === ClientType::Public)) {
            throw InvalidClientMetadata::metadata("token_endpoint_auth_method {$method->value} does not match a {$type->value} client");
        }

        if (($method === TokenEndpointAuthMethod::PrivateKeyJwt) !== ($jwks !== null)) {
            throw InvalidClientMetadata::metadata('token_endpoint_auth_method "private_key_jwt" and a registered JWK Set go together: one was given without the other');
        }
    }

    /**
     * An absolute URI with no fragment (RFC 6749 §3.1.2), over https/http or a
     * reverse-domain private-use scheme (RFC 8252 §7.1) — never a single-word scheme such
     * as `javascript:` that a renderer could execute.
     *
     * @param  list<string>  $uris
     *
     * @throws InvalidClientMetadata
     */
    public static function assertRedirectUris(array $uris, string $field = 'redirect_uris'): void
    {
        foreach ($uris as $uri) {
            $parts = parse_url($uri);

            if ($parts === false || ! isset($parts['scheme'])) {
                throw InvalidClientMetadata::redirectUri("{$field}: not an absolute URI: {$uri}");
            }

            if (isset($parts['fragment'])) {
                throw InvalidClientMetadata::redirectUri("{$field}: must not contain a fragment: {$uri}");
            }

            $scheme = strtolower($parts['scheme']);

            if (($scheme === 'http' || $scheme === 'https') && ! isset($parts['host'])) {
                throw InvalidClientMetadata::redirectUri("{$field}: has no host: {$uri}");
            }

            if ($scheme !== 'http' && $scheme !== 'https' && ! str_contains($scheme, '.')) {
                throw InvalidClientMetadata::redirectUri("{$field}: a custom scheme must be a reverse-domain name (e.g. com.example.app): {$uri}");
            }
        }
    }
}
