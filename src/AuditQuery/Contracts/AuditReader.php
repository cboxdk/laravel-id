<?php

declare(strict_types=1);

namespace Cbox\Id\AuditQuery\Contracts;

use Cbox\Id\AuditQuery\ValueObjects\AuditPage;
use Cbox\Id\AuditQuery\ValueObjects\AuditQueryFilter;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;

/**
 * The authorized read/query surface over the append-only audit trail, and a
 * pull-based stream for SIEM integrations.
 */
interface AuditReader
{
    public function query(AuditQueryFilter $filter): AuditPage;

    /**
     * Entries after a sequence (oldest first) — for a SIEM that polls a cursor.
     *
     * @return list<AuditEntry>
     */
    public function since(?string $organizationId, int $afterSequence, int $limit = 100): array;
}
