<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

/**
 * The scopes no client may grant itself (`cbox-id.oauth.reserved_scopes`): a dynamically
 * registered client is refused them at registration and on every save.
 */
final class ReservedScopes
{
    /**
     * @return list<string>
     */
    public static function all(): array
    {
        $configured = config('cbox-id.oauth.reserved_scopes', []);

        return is_array($configured)
            ? array_values(array_filter($configured, static fn (mixed $scope): bool => is_string($scope) && $scope !== ''))
            : [];
    }
}
