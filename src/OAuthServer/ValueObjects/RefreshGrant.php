<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * The trusted result of rotating a refresh token: the newly-minted refresh token
 * (raw, returned once) plus the grant context it carries forward.
 */
readonly class RefreshGrant
{
    /**
     * @param  list<string>  $scopes
     * @param  list<string>  $amr  the methods used at the ORIGINAL login, not at
     *                             this refresh — see {@see $authTime}
     */
    public function __construct(
        public string $refreshToken,
        public string $clientId,
        public ?string $userId,
        public ?string $organizationId,
        public array $scopes,
        public ?string $audience,

        /**
         * When the user actually authenticated, carried by the rotation family.
         *
         * OIDC Core §12.2: an `auth_time` in a refreshed ID Token must describe
         * the original authentication, not the refresh. Null for a family issued
         * before this was recorded, or for a grant with no user behind it.
         */
        public ?int $authTime = null,
        public array $amr = [],
    ) {}
}
