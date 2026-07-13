<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Contracts;

/**
 * An environment is the HARD isolation boundary of the platform — its own user
 * pool, signing keys, issuer and organization tree (staging vs production, or a
 * per-product / white-label separation).
 *
 * It sits ABOVE the {@see Tenant} (organization) dimension: organizations,
 * users, clients and connections all live inside exactly one environment, and
 * NO kernel escape hatch on the organization dimension (`withoutScope`,
 * `scopedTo` roll-up) may ever cross an environment boundary.
 */
interface Environment
{
    /**
     * The stable, unique identifier of this environment — the exact value stored
     * in environment-owned rows' environment column (default `environment_id`)
     * and compared against on every scoped query.
     */
    public function environmentKey(): string;
}
