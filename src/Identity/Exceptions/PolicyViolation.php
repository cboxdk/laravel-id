<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Exceptions;

use RuntimeException;

/**
 * A credential was refused because it does not satisfy the tenant's authentication
 * policy. The message names the rule that failed so the caller can tell the person what
 * to do differently — a refusal with no reason just gets retried.
 */
class PolicyViolation extends RuntimeException
{
    public static function tooShort(int $minLength): self
    {
        return new self("The password must be at least {$minLength} characters.");
    }

    public static function breached(): self
    {
        return new self('That password has appeared in a public data breach — choose another.');
    }

    public static function reused(int $history): self
    {
        return new self("That password was used recently — it cannot match the last {$history}.");
    }

    public static function passwordLoginDisabled(): self
    {
        return new self('This organization signs in through its identity provider; password sign-in is disabled.');
    }
}
