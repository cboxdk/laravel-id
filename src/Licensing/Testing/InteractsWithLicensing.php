<?php

declare(strict_types=1);

namespace Cbox\Id\Licensing\Testing;

use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;
use Cbox\Id\Licensing\LicenseAwareEntitlements;
use Cbox\Id\Licensing\LicenseSigner;
use Cbox\Id\Licensing\LicenseState;
use Cbox\Id\Licensing\ValueObjects\License;
use Illuminate\Support\Carbon;

/**
 * Installs a real, freshly-signed on-prem license in a test: generates an Ed25519
 * keypair, mints a token, wires the public key + token into config, and resets the
 * resolved license so the next entitlement read reflects it. Uses genuine crypto —
 * no mock verifier.
 *
 *     $this->installLicense(['feature.sso' => ['enabled' => true]]);
 */
trait InteractsWithLicensing
{
    /**
     * @param  array<string, array<string, mixed>>  $entitlements
     * @param  array<string, mixed>  $overrides
     */
    protected function installLicense(array $entitlements = ['platform' => ['enabled' => true]], array $overrides = []): License
    {
        $keypair = sodium_crypto_sign_keypair();
        $now = Carbon::now()->getTimestamp();

        $license = new License(
            id: self::overrideString($overrides, 'id', 'lic_test'),
            customer: self::overrideString($overrides, 'customer', 'cus_test'),
            deployment: array_key_exists('deployment', $overrides) && is_string($overrides['deployment']) ? $overrides['deployment'] : null,
            domains: self::overrideStringList($overrides, 'domains'),
            plan: self::overrideString($overrides, 'plan', 'enterprise'),
            entitlements: $entitlements,
            issuedAt: self::overrideInt($overrides, 'issuedAt', $now),
            notBefore: self::overrideInt($overrides, 'notBefore', $now),
            expiresAt: self::overrideInt($overrides, 'expiresAt', $now + 86400),
        );

        $token = (new LicenseSigner(sodium_crypto_sign_secretkey($keypair)))->sign($license);

        config()->set('cbox-id.license.public_key', base64_encode(sodium_crypto_sign_publickey($keypair)));
        config()->set('cbox-id.license.key', $token);

        app()->forgetInstance(LicenseState::class);
        app()->forgetInstance(LicenseAwareEntitlements::class);
        app()->forgetInstance(EntitlementReader::class);

        return $license;
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    private static function overrideString(array $overrides, string $key, string $default): string
    {
        return array_key_exists($key, $overrides) && is_string($overrides[$key]) ? $overrides[$key] : $default;
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    private static function overrideInt(array $overrides, string $key, int $default): int
    {
        return array_key_exists($key, $overrides) && is_int($overrides[$key]) ? $overrides[$key] : $default;
    }

    /**
     * @param  array<string, mixed>  $overrides
     * @return list<string>
     */
    private static function overrideStringList(array $overrides, string $key): array
    {
        $value = $overrides[$key] ?? null;

        if (! is_array($value)) {
            return [];
        }

        $out = [];

        foreach ($value as $item) {
            if (is_string($item)) {
                $out[] = $item;
            }
        }

        return $out;
    }
}
