<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\ValueObjects;

/**
 * A provider's token response, normalised. Held in memory only, between the HTTP call
 * and the vault — never logged, never serialised.
 */
readonly class PipeTokenSet
{
    /**
     * @param  list<string>|null  $scopes  what the provider says it granted; null when it did not say
     * @param  array<string, string>  $metadata  the catalogue's `metadataPaths`, never a credential
     */
    public function __construct(
        public string $accessToken,
        public ?string $refreshToken,
        public ?int $expiresIn,
        public ?array $scopes,
        public array $metadata,
        public ?string $accountLabel,
    ) {}
}
