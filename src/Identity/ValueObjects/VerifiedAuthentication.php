<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

use Cbox\Id\Identity\Enums\AuthenticationIssuance;

/** Server-owned facts; a missing authentication time never means fresh proof. */
readonly class VerifiedAuthentication
{
    /** @param list<string> $amr */
    public function __construct(
        public string $subjectId,
        public ?string $organizationId,
        public array $amr,
        public ?int $authenticatedAt,
        public AuthenticationIssuance $issuance,
        public ?string $ip = null,
        public ?string $userAgent = null,
    ) {}
}
