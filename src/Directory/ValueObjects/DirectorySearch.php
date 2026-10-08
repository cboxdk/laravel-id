<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\ValueObjects;

use Cbox\Id\Scim\Enums\ScimSortOrder;

/**
 * A SCIM list query (RFC 7644 §3.4.2): the `filter` expression (empty for none), the
 * `startIndex`/`count` pagination parameters (null when the client omitted them), and
 * `sortBy`/`sortOrder` (§3.4.2.3; `sortBy` null for the store's default order).
 */
readonly class DirectorySearch
{
    public function __construct(
        public string $filter = '',
        public ?int $startIndex = null,
        public ?int $count = null,
        public ?string $sortBy = null,
        public ScimSortOrder $sortOrder = ScimSortOrder::Ascending,
    ) {}
}
