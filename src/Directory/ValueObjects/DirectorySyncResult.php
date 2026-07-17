<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\ValueObjects;

/**
 * The outcome of a directory pull: how many users were provisioned (created or
 * updated) and how many were deprovisioned (present before, gone from the provider).
 */
final readonly class DirectorySyncResult
{
    public function __construct(
        public int $provisioned,
        public int $deprovisioned,
        public int $groupsSynced = 0,
    ) {}
}
