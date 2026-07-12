<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Contracts;

use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\ValueObjects\ScimUser;

interface DirectorySync
{
    /**
     * Create or update a user from a SCIM resource: provision the local user,
     * link it, and manage its org membership. Deactivation revokes access.
     */
    public function provisionUser(string $directoryId, ScimUser $user): DirectoryUser;

    /**
     * Deprovision (SCIM delete / active=false): deactivate, drop membership, and
     * revoke the user's sessions immediately.
     */
    public function deprovisionUser(string $directoryId, string $externalId): void;
}
