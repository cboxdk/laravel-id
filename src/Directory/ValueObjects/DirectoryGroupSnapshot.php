<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\ValueObjects;

use Cbox\Id\Directory\Models\DirectoryGroup;

/**
 * A group as seen at the provider: its stable id, display name, and the external
 * ids of its members. Members are resolved to directory-user ids during
 * reconciliation, so a group maps onto the same {@see DirectoryGroup}
 * as SCIM Groups — and feeds the same group→role mappings.
 */
readonly class DirectoryGroupSnapshot
{
    /**
     * @param  list<string>  $memberExternalIds
     */
    public function __construct(
        public string $externalId,
        public string $displayName,
        public array $memberExternalIds = [],
    ) {}
}
