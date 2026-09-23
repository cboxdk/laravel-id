<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\ValueObjects;

/**
 * The attributes of an organization a caller wants changed. A null field is "leave as
 * it is", so a rename does not have to restate the slug. `new OrganizationChanges` is a
 * valid, empty change set.
 */
readonly class OrganizationChanges
{
    public function __construct(
        public ?string $name = null,
        public ?string $slug = null,
    ) {}

    public function isEmpty(): bool
    {
        return $this->name === null && $this->slug === null;
    }
}
