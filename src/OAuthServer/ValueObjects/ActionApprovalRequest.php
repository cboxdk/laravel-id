<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use DateTimeImmutable;

/**
 * A request for a person to approve one action: the handle the host polls and spends,
 * what the person is shown, and when it lapses.
 */
final readonly class ActionApprovalRequest
{
    public function __construct(
        public string $requestId,
        public string $subjectId,
        public string $bindingMessage,
        public DateTimeImmutable $expiresAt,
        public int $interval,
    ) {}
}
