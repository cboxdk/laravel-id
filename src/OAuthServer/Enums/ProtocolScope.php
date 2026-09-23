<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Enums;

/**
 * The scopes this authorization server itself defines — OpenID Connect's, plus the
 * identity extensions (`organizations`, `groups`) that UserInfo and the ID Token read.
 *
 * They belong to the issuer, not to any API, which gives them three rules:
 *
 *  - an API can never register one (a tenant registering `openid` would own every login);
 *  - they survive when a token is narrowed to one API's scopes, because an OIDC client
 *    audiencing its access token to an API still needs UserInfo to work;
 *  - they are what discovery advertises as `scopes_supported` before any API scope.
 */
enum ProtocolScope: string
{
    case OpenId = 'openid';
    case Profile = 'profile';
    case Email = 'email';
    case OfflineAccess = 'offline_access';
    case Organizations = 'organizations';
    case Groups = 'groups';

    public static function isProtocol(string $scope): bool
    {
        return self::tryFrom($scope) !== null;
    }

    /**
     * @return list<string>
     */
    public static function values(): array
    {
        return array_map(static fn (self $case): string => $case->value, self::cases());
    }
}
