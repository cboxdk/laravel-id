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
     */
    public function __construct(
        public string $userId,
        public ?string $organizationId,
        public array $scopes,
        public ?string $nonce = null,
    ) {}
}
