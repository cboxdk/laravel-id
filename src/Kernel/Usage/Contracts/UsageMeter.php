<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Usage\Contracts;

use DateTimeInterface;

/**
 * Records and reads platform usage as environment- and organization-scoped per-day
 * counters. It is the MEASUREMENT layer: every meaningful event (a login, a token
 * grant, an SSO auth, a SCIM sync, an MFA enrolment, a member added…) becomes a
 * counter that dashboards render and — in time — plan gates read to enforce limits.
 *
 * Metering never enforces; it only counts. Enforcement is the entitlements engine's
 * job, so a gate is simply "read the counter, compare to the plan's allowance".
 *
 * Everything is environment-owned: a counter recorded in one environment is
 * structurally invisible to another. `organizationId` null on a query means "across
 * the whole environment"; null on {@see record()} means the event had no org (a
 * system-scoped count).
 */
interface UsageMeter
{
    /**
     * Increment a metric for the current environment by `$count` (default 1),
     * optionally attributed to an organization. A non-positive count is a no-op.
     */
    public function record(string $metric, int $count = 1, ?string $organizationId = null): void;

    /**
     * The summed count of a metric. `$organizationId` null totals the metric across
     * the whole environment; a value scopes it to that org. `$since`/`$until` bound
     * the day range (inclusive); null means unbounded.
     */
    public function total(
        string $metric,
        ?string $organizationId = null,
        ?DateTimeInterface $since = null,
        ?DateTimeInterface $until = null,
    ): int;

    /**
     * A per-day series for a metric over `[since, until]`, for charts. Days with no
     * activity are omitted (sparse).
     *
     * @return array<string, int> keyed by day (`Y-m-d`) → count
     */
    public function series(
        string $metric,
        ?string $organizationId,
        DateTimeInterface $since,
        DateTimeInterface $until,
    ): array;

    /**
     * A snapshot of every metric's total over `[since, until]` — the shape a usage
     * dashboard or a gate check reads in one call.
     *
     * @return array<string, int> keyed by metric → total
     */
    public function snapshot(
        ?string $organizationId,
        DateTimeInterface $since,
        DateTimeInterface $until,
    ): array;
}
