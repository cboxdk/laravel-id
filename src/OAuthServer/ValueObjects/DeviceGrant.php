<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * An approved device grant, ready to mint a token for.
 */
final readonly class DeviceGrant
{
    /**
     * @param  list<string>  $scopes
     */
    public function __construct(
        public string $userId,
        public ?string $organizationId,
        public array $scopes,
    ) {}
}
