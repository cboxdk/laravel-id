<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\ValueObjects;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;

/**
 * One page of directory resources plus the unpaged total and the effective
 * (clamped) start index — everything a SCIM ListResponse envelope needs, with
 * the query, filtering and pagination already resolved by the Directory module.
 *
 * @template TModel of Model
 */
final class DirectoryPage
{
    /**
     * @param  Collection<int, TModel>  $resources
     */
    public function __construct(
        public readonly Collection $resources,
        public readonly int $total,
        public readonly int $startIndex,
    ) {}
}
