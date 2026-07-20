<?php

declare(strict_types=1);

namespace Cbox\Id\Licensing;

use Cbox\License;
use Cbox\License\Contracts\LicenseVerifier;
use Cbox\License\Enums\LicenseStatus;
use Cbox\License\ValueObjects\VerificationContext;
use Cbox\License\ValueObjects\VerificationResult;
use Illuminate\Support\Carbon;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Resolves (once, memoized) the deployment's license status from the configured
 * token, using the shared {@see License} verifier. Any problem — no key, a
 * bad signature, expiry beyond grace, a binding mismatch — resolves to an
 * unlicensed result (deny-by-default) with a logged reason, never an exception into
 * a request: an install with no/invalid key simply runs the free single-tenant tier.
 */
class LicenseState
{
    private ?VerificationResult $result = null;

    public function __construct(
        private readonly ?LicenseVerifier $verifier,
        private readonly ?string $token,
        private readonly string $deploymentId,
        private readonly ?string $domain,
        private readonly LoggerInterface $logger,
    ) {}

    public function result(): VerificationResult
    {
        return $this->result ??= $this->resolve();
    }

    public function isLicensed(): bool
    {
        return $this->result()->isLicensed();
    }

    private function resolve(): VerificationResult
    {
        if ($this->verifier === null || $this->token === null || $this->token === '') {
            return new VerificationResult(LicenseStatus::Unlicensed, null, 'No license configured.');
        }

        try {
            $result = $this->verifier->verify(
                $this->token,
                new VerificationContext($this->deploymentId, $this->domain, Carbon::now()->toDateTimeImmutable()),
            );
        } catch (Throwable $e) {
            $this->logger->warning('Cbox ID license could not be verified: '.$e->getMessage());

            return new VerificationResult(LicenseStatus::Malformed, null, 'License could not be verified.');
        }

        if (! $result->isLicensed()) {
            $this->logger->warning('Cbox ID license not in force: '.$result->reason);
        }

        return $result;
    }
}
