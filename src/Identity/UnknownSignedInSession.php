<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\SignedInSession;

/**
 * The default {@see SignedInSession}: the package cannot know where a host keeps the
 * session id, so it says nothing, and RP-initiated logout without a verified hint clears
 * the Laravel session as it always has. Bind your own to have that logout end the
 * session row too — and with it, notify the applications it signed the person in to.
 */
class UnknownSignedInSession implements SignedInSession
{
    public function id(): ?string
    {
        return null;
    }
}
