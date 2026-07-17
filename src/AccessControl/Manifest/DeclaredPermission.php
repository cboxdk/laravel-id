<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Manifest;

/**
 * A single permission an app declares — a `feature:action` key (e.g.
 * `invoices:create`) and a human description shown in the console picker.
 */
final readonly class DeclaredPermission
{
    public function __construct(
        public string $key,
        public ?string $description = null,
    ) {}
}
