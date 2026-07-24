<?php

declare(strict_types=1);

namespace Cbox\Id\AuditQuery\ValueObjects;

/**
 * Filter for reading a scope's audit trail. `organizationId` null = system trail.
 * `afterSequence` is the pagination cursor. `targetType`/`targetId` narrow to
 * entries acting *on* a subject — the query behind a data-subject (DSR) export,
 * which needs everything done to a person, not just what they did.
 */
readonly class AuditQueryFilter
{
    public function __construct(
        public ?string $organizationId = null,
        public ?string $action = null,
        public ?string $actorId = null,
        public ?string $targetType = null,
        public ?string $targetId = null,
        public ?int $afterSequence = null,
        public int $limit = 50,
    ) {}
}
