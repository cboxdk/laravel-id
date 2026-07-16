<?php

declare(strict_types=1);

namespace Cbox\Id\Licensing;

use Cbox\Id\Kernel\Authorization\CachedEntitlements;
use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;
use Cbox\Id\Kernel\Authorization\Enums\EnforcementMode;
use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementValue;
use Cbox\Id\Licensing\Console\GenerateLicenseKeypairCommand;
use Cbox\License;
use Cbox\License\Ed25519LicenseVerifier;
use Cbox\License\ValueObjects\LicenseLimits;
use Cbox\License\ValueObjects\VerificationResult;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Psr\Log\LoggerInterface;

/**
 * Wires on-prem licensing: it verifies the configured license once (via the shared
 * {@see License} core) and overlays its deployment-wide grants onto the
 * entitlement reader, so paid capabilities unlock through the SAME gate the online
 * billing projection feeds. With no (or an invalid) license the overlay is empty —
 * the install runs as the free single-tenant tier.
 *
 * Registered after the authorization kernel so it can re-point the EntitlementReader
 * alias to the license-aware decorator; the writer alias is left untouched.
 */
final class LicensingServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(LicenseState::class, function (Application $app): LicenseState {
            $publicKey = $this->configString('cbox-id.license.public_key');

            return new LicenseState(
                $publicKey !== null
                    ? new Ed25519LicenseVerifier($publicKey, $this->configInt('cbox-id.license.grace', 0))
                    : null,
                $this->configString('cbox-id.license.key'),
                $this->configString('cbox-id.license.deployment_id') ?? '',
                $this->deploymentDomain(),
                $app->make(LoggerInterface::class),
            );
        });

        $this->app->singleton(LicenseAwareEntitlements::class, function (Application $app): LicenseAwareEntitlements {
            return new LicenseAwareEntitlements(
                $app->make(CachedEntitlements::class),
                $this->grants($app->make(LicenseState::class)->result()),
            );
        });

        $this->app->alias(LicenseAwareEntitlements::class, EntitlementReader::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([GenerateLicenseKeypairCommand::class]);
        }
    }

    /**
     * A verified license's grants as entitlement values (source: license). The
     * version is the issue time, so re-issuing busts the entitlement cache the same
     * way a billing push does.
     *
     * @return array<string, EntitlementValue>
     */
    private function grants(VerificationResult $result): array
    {
        $license = $result->license;

        if (! $result->isLicensed() || $license === null) {
            return [];
        }

        $version = $license->issuedAt->getTimestamp();
        $grants = [];

        foreach ($result->entitlements() as $key) {
            $grants[$key] = new EntitlementValue($key, ['enabled' => true], EnforcementMode::DecisionApi, EntitlementSource::License, $version);
        }

        foreach ($this->limitGrants($result->limits()) as $key => $value) {
            $grants[$key] = new EntitlementValue($key, $value, EnforcementMode::DecisionApi, EntitlementSource::License, $version);
        }

        return $grants;
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private function limitGrants(?LicenseLimits $limits): array
    {
        if ($limits === null) {
            return [];
        }

        $out = [];

        if ($limits->organizations !== null) {
            $out['limits.organizations'] = ['limit' => $limits->organizations];
        }

        if ($limits->seats !== null) {
            $out['limits.seats'] = ['limit' => $limits->seats];
        }

        if ($limits->environments !== null) {
            $out['limits.environments'] = ['limit' => $limits->environments];
        }

        return $out;
    }

    private function deploymentDomain(): ?string
    {
        $source = $this->configString('cbox-id.license.domain') ?? $this->configString('cbox-id.issuer');

        if ($source === null) {
            return null;
        }

        $host = parse_url($source, PHP_URL_HOST);

        return is_string($host) && $host !== '' ? $host : $source;
    }

    private function configString(string $key): ?string
    {
        $value = config($key);

        return is_string($value) && $value !== '' ? $value : null;
    }

    private function configInt(string $key, int $default): int
    {
        $value = config($key, $default);

        return is_int($value) ? $value : (is_numeric($value) ? (int) $value : $default);
    }
}
