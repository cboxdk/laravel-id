<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

/**
 * The platform's target password-hash algorithm and its cost options — what a
 * verified legacy hash is upgraded TO on the next successful login.
 *
 * `options` stays an array because it is handed straight to PHP's
 * `password_hash()` / `password_needs_rehash()`, whose own signature takes an
 * options array; the keys differ per algorithm family (bcrypt `cost` vs argon's
 * `memory_cost`/`time_cost`/`threads`), so that is a runtime-API boundary rather
 * than a domain shape.
 */
readonly class PasswordHashTarget
{
    /**
     * @param  string  $algorithm  a `PASSWORD_*` constant
     * @param  array<string, int>  $options
     */
    public function __construct(
        public string $algorithm,
        public array $options = [],
    ) {}
}
