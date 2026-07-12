<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

/**
 * The trusted result of verifying a WebAuthn registration ceremony.
 */
final readonly class VerifiedRegistration
{
    /**
     * @param  list<string>  $transports
     */
    public function __construct(
        public string $credentialId,
        public string $publicKey,
        public int $signCount,
        public array $transports = [],
    ) {}
}
