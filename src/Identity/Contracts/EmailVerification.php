<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\Exceptions\InvalidEmailVerification;

interface EmailVerification
{
    /**
     * Issue a single-use verification token binding a subject to the address being
     * confirmed. Returns the raw token to email (only its hash is stored).
     */
    public function issue(string $subjectId, string $email): string;

    /**
     * Consume a token and mark the subject's email verified. Returns the subject id.
     * Throws {@see InvalidEmailVerification} if the
     * token is unknown, expired or already used.
     */
    public function verify(string $token): string;
}
