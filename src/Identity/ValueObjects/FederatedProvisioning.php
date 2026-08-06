<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

/**
 * The outcome of resolving a federated identity: who it is, and whether we had met them
 * before.
 *
 * `provisionFederated()` answered only the first half, which meant a caller could not
 * tell a returning person from a brand-new account. That distinction decides real
 * behaviour: a first-sight federated account is a signup, and a signup has obligations a
 * sign-in does not — the address is unverified until WE verify it, and the person has no
 * password, so they hold exactly one way in and lose the account if the provider is
 * unreachable.
 *
 * Returning it rather than inferring it: a caller that guesses "new" from an unverified
 * email or an absent password will eventually guess wrong about someone who simply never
 * finished setting up.
 */
readonly class FederatedProvisioning
{
    public function __construct(
        public Subject $subject,

        /** True only when this call created the account, not when it matched an existing link. */
        public bool $created,
    ) {}
}
