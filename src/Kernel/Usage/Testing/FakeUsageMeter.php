<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Usage\Testing;

use Cbox\Id\Kernel\Usage\Contracts\UsageMeter;
use Closure;
use DateTimeInterface;
use PHPUnit\Framework\Assert;

/**
 * In-memory {@see UsageMeter} for tests: captures every increment and answers the
 * read methods by aggregating them, plus assertion helpers. Swap it in with
 * {@see InteractsWithUsage::fakeUsage()}.
 */
class FakeUsageMeter implements UsageMeter
{
    /**
     * Every recorded increment, in order.
     *
     * @var list<array{metric: string, count: int, organizationId: ?string}>
     */
    public array $recorded = [];

    public function record(string $metric, int $count = 1, ?string $organizationId = null): void
    {
        if ($count <= 0 || $metric === '') {
            return;
        }

        $this->recorded[] = ['metric' => $metric, 'count' => $count, 'organizationId' => $organizationId];
    }

    public function total(
        string $metric,
        ?string $organizationId = null,
        ?DateTimeInterface $since = null,
        ?DateTimeInterface $until = null,
    ): int {
        $sum = 0;

        foreach ($this->recorded as $entry) {
            if ($entry['metric'] === $metric && $this->orgMatches($entry, $organizationId)) {
                $sum += $entry['count'];
            }
        }

        return $sum;
    }

    public function series(
        string $metric,
        ?string $organizationId,
        DateTimeInterface $since,
        DateTimeInterface $until,
    ): array {
        $total = $this->total($metric, $organizationId);

        return $total > 0 ? [now()->format('Y-m-d') => $total] : [];
    }

    public function snapshot(
        ?string $organizationId,
        DateTimeInterface $since,
        DateTimeInterface $until,
    ): array {
        $snapshot = [];

        foreach ($this->recorded as $entry) {
            if ($this->orgMatches($entry, $organizationId)) {
                $snapshot[$entry['metric']] = ($snapshot[$entry['metric']] ?? 0) + $entry['count'];
            }
        }

        return $snapshot;
    }

    /**
     * Assert a metric was incremented (optionally matching a predicate on an entry).
     *
     * @param  Closure(array{metric: string, count: int, organizationId: ?string}): bool|null  $predicate
     */
    public function assertIncremented(string $metric, ?Closure $predicate = null): void
    {
        $found = false;

        foreach ($this->recorded as $entry) {
            if ($entry['metric'] === $metric && ($predicate === null || $predicate($entry))) {
                $found = true;
                break;
            }
        }

        Assert::assertTrue($found, "Expected usage metric [{$metric}] to have been recorded, but it was not.");
    }

    public function assertIncrementedCount(string $metric, int $times): void
    {
        $actual = count(array_filter($this->recorded, fn (array $e): bool => $e['metric'] === $metric));

        Assert::assertSame($times, $actual, "Expected metric [{$metric}] recorded {$times} time(s), got {$actual}.");
    }

    public function assertNothingRecorded(): void
    {
        Assert::assertSame([], $this->recorded, 'Expected no usage to have been recorded.');
    }

    /**
     * @param  array{metric: string, count: int, organizationId: ?string}  $entry
     */
    private function orgMatches(array $entry, ?string $organizationId): bool
    {
        return $organizationId === null || $entry['organizationId'] === $organizationId;
    }
}
