<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

/**
 * Whether a password appears in a public breach corpus.
 *
 * A contract because the lookup is a network call the host owns (and must be able to
 * fake in tests): the framework decides WHEN the check applies — the policy's
 * `requireBreachCheck` — while the host decides HOW it is answered.
 *
 * The shipped default refuses nothing, so a host that never binds a real implementation
 * does not silently believe it has breach protection it never wired up.
 */
interface BreachedPasswordCheck
{
    public function isBreached(string $password): bool;
}
