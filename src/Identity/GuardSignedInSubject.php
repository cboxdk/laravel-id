<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\SignedInSubject;

/**
 * The default {@see SignedInSubject}: Laravel's own guard.
 *
 * Correct for a host that authenticates people the ordinary way, and the reason this
 * binding exists rather than the call being inlined — a host that keeps its own session
 * binds its own implementation instead of discovering, silently, that logout does nothing.
 */
class GuardSignedInSubject implements SignedInSubject
{
    public function id(): ?string
    {
        $id = auth()->id();

        return is_string($id) || is_int($id) ? (string) $id : null;
    }
}
