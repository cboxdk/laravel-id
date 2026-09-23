<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\ValueObjects;

use DateTimeInterface;

/**
 * A request to issue a customer API key: WHO holds it (`userId` in `organizationId`),
 * WHICH app it is for (`clientId`, the public OAuth client id), and the subset of that
 * app's permissions it may carry.
 *
 * `permissions` must be a subset of what the holder currently holds for the app —
 * checked at issuance, and re-applied as a ceiling at every verification. An empty list
 * is a valid key that identifies its holder and authorizes nothing.
 *
 * `expiresAt` null means the key does not expire on its own; it still dies with the
 * holder's membership and is revoked explicitly.
 */
readonly class NewCustomerApiKey
{
    /**
     * @param  list<string>  $permissions
     */
    public function __construct(
        public string $organizationId,
        public string $userId,
        public string $clientId,
        public array $permissions = [],
        public ?string $name = null,
        public ?DateTimeInterface $expiresAt = null,
    ) {}
}
