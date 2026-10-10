<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Exceptions;

use Cbox\Id\Identity\Contracts\SignInMethods;
use RuntimeException;

/**
 * A sign-in method this environment, or this deployment, has switched off was asked for
 * anyway ({@see SignInMethods}).
 *
 * Thrown by the credential primitives themselves — the magic-link service and the passkey
 * service — rather than left to a host's routes, so a host that adds a door of its own (an
 * embedded sign-in, a CLI) cannot forget to ask. A host is expected to ask first and not
 * draw the method at all; this is what holds when it did not.
 */
class SignInMethodDisabled extends RuntimeException
{
    /** Which method was refused: `passkeys` or `magic_link`. */
    public string $method = '';

    /** @param 'passkeys'|'magic_link' $method */
    public static function make(string $method): self
    {
        $exception = new self(match ($method) {
            'passkeys' => 'Passkeys are turned off for this environment.',
            'magic_link' => 'Magic links are turned off for this environment.',
        });
        $exception->method = $method;

        return $exception;
    }
}
