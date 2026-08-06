<?php

declare(strict_types=1);

namespace Cbox\Id\AuditQuery\ValueObjects;

use Cbox\Id\Kernel\Audit\Models\AuditEntry;

readonly class AuditPage
{
    /**
     * @param  list<AuditEntry>  $items
     */
    public function __construct(
        public array $items,
        public ?string $nextCursor,
    ) {}
}
