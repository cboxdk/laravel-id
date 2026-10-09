<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\ValueObjects;

use DateTimeImmutable;

/**
 * A fresh access token for one person's connected account, leased to an authorised app
 * for immediate use. The plaintext lives in this object in memory only.
 *
 * Two different expiries, and the difference matters:
 *
 *  - `expiresAt` is the PROVIDER's — when the token stops working at GitHub or Google.
 *    Null for tokens that do not expire.
 *  - `leaseExpiresAt` is the VAULT's advisory window — when the app is expected to have
 *    dropped the value and come back for a new one, which may be a refreshed token.
 *
 * `metadata` carries the non-secret parts of the token response the app needs to call the
 * API at all, such as Salesforce's `instance_url`.
 */
readonly class PipeAccessToken
{
    /**
     * @param  list<string>  $scopes
     * @param  array<string, string>  $metadata
     */
    public function __construct(
        public string $connectionId,
        public string $provider,
        public string $userId,
        public string $accessToken,
        public ?DateTimeImmutable $expiresAt,
        public DateTimeImmutable $leaseExpiresAt,
        public array $scopes,
        public array $metadata,
        public string $tokenType = 'Bearer',
    ) {}
}
