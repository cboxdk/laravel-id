<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Usage;

use Cbox\Id\Kernel\Usage\Contracts\UsageMeter;
use Cbox\Id\Kernel\Usage\Models\UsageCounter;
use DateTimeInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;

/**
 * Database-backed {@see UsageMeter}. Counters are per-day rows; a record is an atomic
 * find-or-create of the day's row followed by an atomic `count = count + n` UPDATE.
 * The unique index on `(environment_id, organization_id, metric, period)` plus a
 * transaction retry serialise a raced create (the house pattern, SQLite-portable), so
 * a concurrent increment is never lost.
 */
final class DatabaseUsageMeter implements UsageMeter
{
    public function __construct(private readonly bool $enabled = true) {}

    public function record(string $metric, int $count = 1, ?string $organizationId = null): void
    {
        if (! $this->enabled || $count <= 0 || $metric === '') {
            return;
        }

        $organization = $organizationId ?? '';
        $period = now()->format('Y-m-d');

        DB::transaction(function () use ($metric, $count, $organization, $period): void {
            // environment_id is auto-filled + scoped by BelongsToEnvironment.
            $counter = UsageCounter::query()->firstOrCreate(
                ['organization_id' => $organization, 'metric' => $metric, 'period' => $period],
                ['count' => 0],
            );

            // A single UPDATE ... SET count = count + n — atomic at the DB layer.
            $counter->increment('count', $count);
        }, attempts: 3);
    }

    public function total(
        string $metric,
        ?string $organizationId = null,
        ?DateTimeInterface $since = null,
        ?DateTimeInterface $until = null,
    ): int {
        $query = UsageCounter::query()->where('metric', $metric);
        $this->scopeOrg($query, $organizationId);
        $this->scopePeriod($query, $since, $until);

        return (int) $query->sum('count');
    }

    public function series(
        string $metric,
        ?string $organizationId,
        DateTimeInterface $since,
        DateTimeInterface $until,
    ): array {
        $query = UsageCounter::query()->where('metric', $metric);
        $this->scopeOrg($query, $organizationId);
        $this->scopePeriod($query, $since, $until);

        $rows = $query->selectRaw('period, SUM(count) as total')
            ->groupBy('period')
            ->orderBy('period')
            ->pluck('total', 'period');

        $series = [];
        foreach ($rows as $period => $total) {
            if (is_string($period) && is_numeric($total)) {
                $series[$period] = (int) $total;
            }
        }

        return $series;
    }

    public function snapshot(
        ?string $organizationId,
        DateTimeInterface $since,
        DateTimeInterface $until,
    ): array {
        $query = UsageCounter::query();
        $this->scopeOrg($query, $organizationId);
        $this->scopePeriod($query, $since, $until);

        $rows = $query->selectRaw('metric, SUM(count) as total')
            ->groupBy('metric')
            ->pluck('total', 'metric');

        $snapshot = [];
        foreach ($rows as $metric => $total) {
            if (is_string($metric) && is_numeric($total)) {
                $snapshot[$metric] = (int) $total;
            }
        }

        return $snapshot;
    }

    /**
     * @param  Builder<UsageCounter>  $query
     */
    private function scopeOrg(Builder $query, ?string $organizationId): void
    {
        if ($organizationId !== null) {
            $query->where('organization_id', $organizationId);
        }
    }

    /**
     * @param  Builder<UsageCounter>  $query
     */
    private function scopePeriod(Builder $query, ?DateTimeInterface $since, ?DateTimeInterface $until): void
    {
        if ($since !== null) {
            $query->where('period', '>=', $since->format('Y-m-d'));
        }

        if ($until !== null) {
            $query->where('period', '<=', $until->format('Y-m-d'));
        }
    }
}
