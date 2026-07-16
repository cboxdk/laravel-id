<?php

declare(strict_types=1);

namespace Cbox\Id\Licensing\Testing;

use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;
use Cbox\Id\Licensing\LicenseAwareEntitlements;
use Cbox\Id\Licensing\LicenseState;
use Cbox\License;
use Cbox\License\Ed25519LicenseIssuer;
use Cbox\License\Support\Ed25519KeyPair;
use Cbox\License\ValueObjects\LicenseLimits;
use Cbox\License\ValueObjects\LicenseRequest;
use Illuminate\Support\Carbon;

/**
 * Installs a real, freshly-signed on-prem license in a test: generates an Ed25519
 * keypair, mints a token with the shared {@see License} issuer, wires the
 * public key + token into config, and resets the resolved license so the next
 * entitlement read reflects it. Genuine crypto — no mock verifier.
 *
 *     $this->installLicense([Capabilities::SSO]);
 */
trait InteractsWithLicensing
{
    /**
     * @param  list<string>  $entitlements
     * @param  array<string, mixed>  $overrides
     */
    protected function installLicense(array $entitlements = ['platform.multi_tenant'], array $overrides = []): void
    {
        $keys = Ed25519KeyPair::generate();
        $now = Carbon::now()->toDateTimeImmutable();

        $deploymentId = self::overrideString($overrides, 'deploymentId', 'dep_test');
        $domain = array_key_exists('domain', $overrides) && is_string($overrides['domain']) ? $overrides['domain'] : null;

        $token = (new Ed25519LicenseIssuer($keys['privateKey']))->issue(new LicenseRequest(
            plan: self::overrideString($overrides, 'plan', 'enterprise'),
            entitlements: $entitlements,
            limits: new LicenseLimits,
            customerId: self::overrideString($overrides, 'customerId', 'cus_test'),
            deploymentId: $deploymentId,
            licensedDomain: $domain,
            issuedAt: $now,
            notBefore: $now,
            expiresAt: $now->modify(self::overrideString($overrides, 'expires', '+1 day')),
        ));

        config()->set('cbox-id.license.public_key', $keys['publicKey']);
        config()->set('cbox-id.license.key', $token);
        config()->set('cbox-id.license.deployment_id', $deploymentId);

        app()->forgetInstance(LicenseState::class);
        app()->forgetInstance(LicenseAwareEntitlements::class);
        app()->forgetInstance(EntitlementReader::class);
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    private static function overrideString(array $overrides, string $key, string $default): string
    {
        return array_key_exists($key, $overrides) && is_string($overrides[$key]) ? $overrides[$key] : $default;
    }
}
