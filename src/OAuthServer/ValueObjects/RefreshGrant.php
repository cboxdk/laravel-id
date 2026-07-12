<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * The trusted result of rotating a refresh token: the newly-minted refresh token
 * (raw, returned once) plus the grant context it carries forward.
 */
final readonly class RefreshGrant
{
    /**
     * @param  list<string>  $scopes
     */
    public function __construct(
        public string $refreshToken,
        public string $clientId,
        public ?string $userId,
        public ?string $organizationId,
        public array $scopes,
        public ?string $audience,
    ) {}
}
