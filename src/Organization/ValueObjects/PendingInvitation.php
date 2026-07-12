<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\ValueObjects;

use Cbox\Id\Organization\Models\Invitation;

/**
 * Returned once when an invitation is created: the record plus its plaintext
 * token (emailed to the invitee, never retrievable again — only the hash is
 * stored).
 */
final readonly class PendingInvitation
{
    public function __construct(
        public Invitation $invitation,
        public string $token,
    ) {}
}
