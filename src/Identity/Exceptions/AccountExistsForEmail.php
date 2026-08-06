<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Exceptions;

use RuntimeException;

/**
 * Thrown when a first-seen federated identity presents an email that already
 * belongs to an account. The platform never merges accounts on the strength of a
 * provider-supplied email — the user must sign in with their existing method and
 * link the new provider deliberately. This is what prevents account takeover via
 * a provider that returns someone else's (or an unverified) email.
 */
class AccountExistsForEmail extends RuntimeException
{
    public static function make(string $email): self
    {
        return new self("An account already exists for [{$email}]; link the provider explicitly instead of merging.");
    }
}
