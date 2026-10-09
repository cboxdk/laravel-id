<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Exceptions;

use InvalidArgumentException;

/**
 * A pipe configuration the platform refuses to store: a provider the catalogue does not
 * have, a parameter that does not match its pattern, or a client id / secret that is
 * blank. The message is safe to show an administrator — it never repeats the secret.
 */
class InvalidPipeConfiguration extends InvalidArgumentException
{
    public static function unknownProvider(string $provider): self
    {
        return new self("There is no pipe provider [{$provider}].");
    }

    public static function parameter(string $provider, string $parameter): self
    {
        return new self("The [{$parameter}] value is not valid for the {$provider} pipe.");
    }

    public static function blank(string $field): self
    {
        return new self("The pipe's {$field} must not be empty.");
    }

    public static function alreadyConfigured(string $provider): self
    {
        return new self("A {$provider} pipe is already configured in this environment.");
    }
}
