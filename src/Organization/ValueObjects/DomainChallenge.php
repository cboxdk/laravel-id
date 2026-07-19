<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\ValueObjects;

/**
 * A pending (or just-completed) custom-domain verification for an environment. The
 * operator publishes a DNS TXT record named {@see $recordName} with value
 * {@see $recordValue}; once that record is live, verification promotes {@see $domain}
 * to the environment's issuer host. Carrying the exact record to publish as a typed
 * object keeps the console from re-deriving the challenge string in a view.
 */
final readonly class DomainChallenge
{
    public function __construct(
        public string $domain,
        public string $recordName,
        public string $recordValue,
        public bool $verified = false,
    ) {}
}
