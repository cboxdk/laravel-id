<?php

declare(strict_types=1);

namespace Cbox\Id\AuditQuery;

use Cbox\Id\AuditQuery\Contracts\AuditReader;
use Cbox\Id\AuditQuery\ValueObjects\AuditPage;
use Cbox\Id\AuditQuery\ValueObjects\AuditQueryFilter;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Illuminate\Database\Eloquent\Builder;

final class DatabaseAuditReader implements AuditReader
{
    public function query(AuditQueryFilter $filter): AuditPage
    {
        $limit = max(1, min(500, $filter->limit));

        $rows = $this->scoped($filter->organizationId)
            ->when($filter->action !== null, fn (Builder $q) => $q->where('action', $filter->action))
            ->when($filter->actorId !== null, fn (Builder $q) => $q->where('actor_id', $filter->actorId))
            ->when($filter->afterSequence !== null, fn (Builder $q) => $q->where('sequence', '>', $filter->afterSequence))
            ->orderBy('sequence')
            ->limit($limit + 1)
            ->get();

        $hasMore = $rows->count() > $limit;
        $items = $rows->take($limit)->values();
        $last = $items->last();

        return new AuditPage(
            array_values($items->all()),
            $hasMore && $last !== null ? (string) $last->sequence : null,
        );
    }

    public function since(?string $organizationId, int $afterSequence, int $limit = 100): array
    {
        $rows = $this->scoped($organizationId)
            ->where('sequence', '>', $afterSequence)
            ->orderBy('sequence')
            ->limit(max(1, min(1000, $limit)))
            ->get();

        return array_values($rows->all());
    }

    /**
     * @return Builder<AuditEntry>
     */
    private function scoped(?string $organizationId): Builder
    {
        $query = AuditEntry::query();

        return $organizationId !== null
            ? $query->where('organization_id', $organizationId)
            : $query->whereNull('organization_id');
    }
}
