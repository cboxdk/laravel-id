<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use InvalidArgumentException;

/**
 * One logout token to deliver: to which client, about whom.
 *
 * Back-Channel Logout 1.0 §2.4: a logout token MUST carry `sub`, `sid`, or both. `sub`
 * alone means "every session of this person at your application"; with `sid` it means
 * "that one". Enforced here so a notice that could only produce a non-conformant token
 * cannot be built at all.
 */
readonly class LogoutNotice
{
    public function __construct(
        public string $clientId,
        public ?string $subject,
        public ?string $sid = null,
    ) {
        if ($subject === null && $sid === null) {
            throw new InvalidArgumentException('A logout notice needs a subject, a sid, or both.');
        }
    }
}
