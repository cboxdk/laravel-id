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
     * How many entries a filter matches, without reading any of them.
     *
     * `afterSequence` and `limit` are ignored — this counts the whole match, which is the
     * only question a count answers. Exists because the alternative, and what the compliance
     * console actually did, is to cursor through every page of a subject's entire audit
     * history to call `count()` on the result — on a live-updating input, so a half-typed
     * subject id swept the lot.
     */
    public function count(AuditQueryFilter $filter): int;

    /**
     * Entries after a sequence (oldest first) — for a SIEM that polls a cursor.
     *
     * @return list<AuditEntry>
     */
    public function since(?string $organizationId, int $afterSequence, int $limit = 100): array;
}
