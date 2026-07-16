<?php

declare(strict_types=1);

namespace Cbox\Id\Licensing;

use Cbox\Id\Kernel\Authorization\CachedEntitlements;
use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;
use Cbox\Id\Licensing\Console\GenerateLicenseKeypairCommand;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Psr\Log\LoggerInterface;

/**
 * Wires on-prem licensing: it resolves the configured license once and overlays its
 * deployment-wide grants onto the entitlement reader, so paid capabilities unlock
 * through the SAME gate the online billing projection feeds. With no (or an invalid)
 * license the overlay is empty — the install runs as the free single-tenant tier.
 *
 * Registered after the authorization kernel so it can re-point the EntitlementReader
 * alias to the license-aware decorator; the writer alias is left untouched.
 */
final class LicensingServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(LicenseState::class, function (Application $app): LicenseState {
            $publicKey = $this->publicKey();

            return new LicenseState(
                $publicKey !== null ? new Ed25519LicenseVerifier($publicKey) : null,
                $this->configString('cbox-id.license.key'),
                $this->deploymentDomain(),
                $app->make(LoggerInterface::class),
            );
        });

        $this->app->singleton(LicenseAwareEntitlements::class, function (Application $app): LicenseAwareEntitlements {
            $license = $app->make(LicenseState::class)->current();

            return new LicenseAwareEntitlements(
                $app->make(CachedEntitlements::class),
                $license?->entitlementValues() ?? [],
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
     * The raw Ed25519 public key from config, or null if unset/misconfigured (in
     * which case licenses can't be verified and the install stays free-tier).
     */
    private function publicKey(): ?string
    {
        $encoded = $this->configString('cbox-id.license.public_key');

        if ($encoded === null) {
            return null;
        }

        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);

        return $decoded !== false && strlen($decoded) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES ? $decoded : null;
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
}
