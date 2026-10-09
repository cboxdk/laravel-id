<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Hris\ValueObjects;

/**
 * A department (or org unit, team, cost centre — whatever the HR system calls the unit
 * people are filed under) as the HR system reports it. Becomes a directory GROUP, so the
 * same group→role mappings SCIM groups feed apply to departments unchanged.
 */
readonly class HrisDepartment
{
    public function __construct(
        /** The HR system's stable id. Names change; ids do not. */
        public string $id,
        public string $name,
        public ?string $parentId = null,
    ) {}
}
