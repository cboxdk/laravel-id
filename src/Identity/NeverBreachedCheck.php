<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\BreachedPasswordCheck;

/**
 * The shipped default {@see BreachedPasswordCheck}: it knows of no breaches.
 *
 * Deliberately inert rather than absent. Checking a password against a breach corpus
 * means a network lookup against a service the HOST chooses and operates, which a
 * dependency-light library must not impose. Binding a do-nothing default keeps the
 * policy path working out of the box — and the honest-crypto stance forbids pretending
 * otherwise, so a host that has not wired a real check gets no false assurance: this
 * class's name says exactly what it does.
 */
class NeverBreachedCheck implements BreachedPasswordCheck
{
    public function isBreached(string $password): bool
    {
        return false;
    }
}
