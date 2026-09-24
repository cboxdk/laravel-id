<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Enums;

use Cbox\Id\Api\Http\Controllers\TokenController;
use Cbox\Id\OAuthServer\Support\GrantPolicy;

/**
 * The grants the token endpoint implements, and so the only ones a client may be
 * registered for.
 *
 * `grant_types` on a client stays a list of strings — it is the RFC 7591 wire value, and
 * {@see GrantPolicy} compares strings — but anything WRITTEN
 * there passes through this enum first, so a typo is refused at registration rather than
 * discovered as `unauthorized_client` at the first token request.
 */
enum GrantType: string
{
    case AuthorizationCode = 'authorization_code';
    case RefreshToken = 'refresh_token';
    case ClientCredentials = 'client_credentials';
    case DeviceCode = 'urn:ietf:params:oauth:grant-type:device_code';
    case Ciba = 'urn:openid:params:grant-type:ciba';
    case TokenExchange = 'urn:ietf:params:oauth:grant-type:token-exchange';

    /**
     * Whether only a confidential client may be registered for this grant.
     *
     * Token exchange turns one token into another for a different audience or a narrower
     * scope. RFC 8693 §2.1 leaves client authentication to the server, and this server
     * requires it ({@see TokenController}): a public client
     * could present anybody's token it came across. Registering one for it would promise
     * a grant the token endpoint then refuses on every call.
     */
    public function requiresConfidentialClient(): bool
    {
        return $this === self::TokenExchange;
    }
}
