<?php

declare(strict_types=1);

namespace Cbox\Id\AuditQuery\ValueObjects;

/**
 * Filter for reading a scope's audit trail. `organizationId` null = system trail.
 * `afterSequence` is the pagination cursor.
 */
final readonly class AuditQueryFilter
{
    public function __construct(
        public ?string $organizationId = null,
        public ?string $action = null,
        public ?string $actorId = null,
        public ?int $afterSequence = null,
        public int $limit = 50,
    ) {}
}
