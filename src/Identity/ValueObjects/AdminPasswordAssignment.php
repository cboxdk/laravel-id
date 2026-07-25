<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

use Cbox\Id\Identity\Enums\PasswordRevocationScope;
use Illuminate\Support\Carbon;

/**
 * An administrator setting a subject's password directly.
 *
 * This platform OWNS its user records, so administrative credential recovery is a
 * first-party capability rather than something delegated to an upstream provider —
 * but it is only legitimate when it is authorized, deliberate and auditable, which is
 * why every choice here is explicit rather than implied by a default.
 */
readonly class AdminPasswordAssignment
{
    /**
     * @param  string  $userId  the subject whose credential is being replaced
     * @param  string  $password  the new plaintext password (hashed on write)
     * @param  bool  $temporary  true → the subject MUST choose a new password at next
     *                           sign-in; the assigned one is a hand-off credential only
     * @param  Carbon|null  $expiresAt  when a temporary password stops working entirely;
     *                                  null leaves it usable until changed
     * @param  PasswordRevocationScope  $revoke  how much existing access this invalidates
     * @param  string|null  $actorType  who performed it, recorded on the audit event
     */
    public function __construct(
        public string $userId,
        public string $password,
        public bool $temporary = true,
        public ?Carbon $expiresAt = null,
        public PasswordRevocationScope $revoke = PasswordRevocationScope::SessionsAndTokens,
        public ?string $actorType = null,
        public ?string $actorId = null,
        public ?string $reason = null,
        /** Whose policy applies — the organization context this assignment is made in. */
        public ?string $organizationId = null,
    ) {}
}
