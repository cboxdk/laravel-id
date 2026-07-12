<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Exceptions;

use RuntimeException;

/**
 * Thrown when a WebAuthn client response fails verification — malformed JSON,
 * wrong ceremony type, challenge/origin/RP-id mismatch, or a bad signature.
 * Never carries key material.
 */
final class InvalidAssertionResponse extends RuntimeException
{
    public static function make(string $reason): self
    {
        return new self('invalid WebAuthn response: '.$reason);
    }
}
