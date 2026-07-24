<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Exceptions;

use RuntimeException;

/**
 * Thrown when a SCIM create/replace would give two users in the same directory the
 * same `userName`. The ServiceProviderConfig advertises `uniqueness=server` for
 * userName, so the server enforces it: a collision is a `409 scimType=uniqueness`,
 * not a silently-provisioned duplicate the IdP can never reconcile.
 */
class DirectoryUserNameTaken extends RuntimeException
{
    public static function make(string $userName): self
    {
        return new self("A user with userName [{$userName}] already exists in this directory.");
    }
}
