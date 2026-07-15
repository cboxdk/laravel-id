<?php

declare(strict_types=1);

namespace Cbox\Id\TokenVault\ValueObjects;

use DateTimeImmutable;

/**
 * A brokered hand-off of a downstream credential to an authorized agent, for
 * immediate use. The plaintext `secret` lives only in this object in memory — it
 * is never persisted, logged, or audited by the vault.
 *
 * `expiresAt` is an ADVISORY lease window: the vault trusts the caller to stop
 * using (and to drop) the value by then. The lease is not a server-side token, so
 * revocation happens at the secret / grant level, which takes effect on the next
 * lease rather than clawing back an in-flight one.
 */
final readonly class SecretLease
{
    public function __construct(
        public string $secretId,
        public string $provider,
        public string $secret,
        public DateTimeImmutable $expiresAt,
    ) {}
}
