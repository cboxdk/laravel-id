<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * An approved device grant, ready to mint a token for.
 */
readonly class DeviceGrant
{
    /**
     * @param  list<string>  $scopes
     * @param  list<string>  $amr  the approving session's methods, empty when unknown
     */
    public function __construct(
        public string $userId,
        public ?string $organizationId,
        public array $scopes,
        public ?int $authTime = null,
        public array $amr = [],
    ) {}
}
