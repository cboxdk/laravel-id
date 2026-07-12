<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * The trusted result of exchanging a valid authorization code (PKCE verified).
 */
final readonly class AuthorizedGrant
{
    /**
     * @param  list<string>  $scopes
     * @param  list<string>  $amr  authentication methods used at login (OIDC amr)
     */
    public function __construct(
        public string $userId,
        public ?string $organizationId,
        public array $scopes,
        public ?string $nonce = null,
        public ?int $authTime = null,
        public array $amr = [],
    ) {}
}
