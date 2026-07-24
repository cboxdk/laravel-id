<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

use Cbox\Id\Identity\Contracts\Subjects;

/**
 * An authenticated identity, as the platform sees it: an opaque string id plus
 * the couple of attributes the platform needs (email/name for tokens and
 * notifications). It is deliberately NOT a host model — the platform references
 * subjects only by their opaque id, so it integrates with any user store: a
 * single users table, an existing app's model, or several authenticatable
 * models (users, admins, resellers) behind one {@see Subjects}
 * resolver.
 */
readonly class Subject
{
    public function __construct(
        public string $id,
        public ?string $email = null,
        public ?string $name = null,
        public bool $emailVerified = false,
    ) {}
}
