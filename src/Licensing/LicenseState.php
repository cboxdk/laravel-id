<?php

declare(strict_types=1);

namespace Cbox\Id\Licensing;

use Cbox\Id\Licensing\Contracts\LicenseVerifier;
use Cbox\Id\Licensing\Exceptions\LicenseException;
use Cbox\Id\Licensing\ValueObjects\License;
use Psr\Log\LoggerInterface;

/**
 * Resolves (once, memoized) the deployment's current license from the configured
 * token: verify the signature + validity, then check the domain binding. Any
 * failure resolves to "no license" (deny-by-default) with a logged reason, never an
 * exception that could break a request — an install with an invalid key simply runs
 * as the free single-tenant tier.
 */
final class LicenseState
{
    private bool $resolved = false;

    private ?License $license = null;

    public function __construct(
        private readonly ?LicenseVerifier $verifier,
        private readonly ?string $token,
        private readonly ?string $expectedDomain,
        private readonly LoggerInterface $logger,
    ) {}

    public function current(): ?License
    {
        if (! $this->resolved) {
            $this->resolved = true;
            $this->license = $this->resolve();
        }

        return $this->license;
    }

    public function isLicensed(): bool
    {
        return $this->current() !== null;
    }

    private function resolve(): ?License
    {
        if ($this->verifier === null || $this->token === null || $this->token === '') {
            return null;
        }

        try {
            $license = $this->verifier->verify($this->token);
        } catch (LicenseException $e) {
            $this->logger->warning('Cbox ID license rejected: '.$e->getMessage());

            return null;
        }

        if (! $this->domainAllowed($license)) {
            $this->logger->warning('Cbox ID license rejected: domain binding mismatch.');

            return null;
        }

        return $license;
    }

    private function domainAllowed(License $license): bool
    {
        // An unbound license (no domains) runs anywhere; if we can't determine our
        // own host, don't fail on the soft binding — the signature + expiry are the
        // hard gates, domain binding is only an anti-sharing hint.
        if ($license->domains === [] || $this->expectedDomain === null || $this->expectedDomain === '') {
            return true;
        }

        $expected = strtolower($this->expectedDomain);

        foreach ($license->domains as $domain) {
            if (strtolower($domain) === $expected) {
                return true;
            }
        }

        return false;
    }
}
