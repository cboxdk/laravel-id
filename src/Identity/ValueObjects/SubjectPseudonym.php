<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

/**
 * The placeholders an erased subject's email and name become.
 *
 * The email is under `.invalid` (RFC 2606 §2): it can never be delivered to, and can
 * never collide with a real address someone later signs up with.
 */
readonly class SubjectPseudonym
{
    public function __construct(
        public string $email,
        public string $name,
    ) {}

    /** Build both placeholders from one opaque token (a keyed hash of the subject id). */
    public static function fromToken(string $token): self
    {
        return new self('erased+'.$token.'@erased.invalid', 'erased-'.$token);
    }
}
