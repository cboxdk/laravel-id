<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Contracts;

/**
 * Marks an Eloquent model whose rows belong to exactly one {@see Environment}.
 * Paired with the BelongsToEnvironment trait, which enforces the hard,
 * always-on environment scope.
 */
interface EnvironmentOwned
{
    /** The column holding the environment key on this model (default `environment_id`). */
    public function environmentColumn(): string;
}
