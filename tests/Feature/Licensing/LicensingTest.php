<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;
use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Cbox\Id\Licensing\Ed25519LicenseVerifier;
use Cbox\Id\Licensing\Exceptions\LicenseException;
use Cbox\Id\Licensing\LicenseAwareEntitlements;
use Cbox\Id\Licensing\LicenseSigner;
use Cbox\Id\Licensing\LicenseState;
use Cbox\Id\Licensing\ValueObjects\License;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;

uses(RefreshDatabase::class);

/**
 * Mint a real, signed token with a fresh keypair. Returns [token, rawPublicKey].
 *
 * @param  array<string, array<string, mixed>>  $ent
 * @return array{0: string, 1: string}
 */
function mintLicense(int $iat, int $nbf, int $exp, array $ent = ['platform' => ['enabled' => true]]): array
{
    $keypair = sodium_crypto_sign_keypair();
    $license = new License('lic_1', 'cus_1', null, [], 'enterprise', $ent, $iat, $nbf, $exp);
    $token = (new LicenseSigner(sodium_crypto_sign_secretkey($keypair)))->sign($license);

    return [$token, sodium_crypto_sign_publickey($keypair)];
}

it('verifies a well-formed license and decodes its claims', function (): void {
    $now = Carbon::now()->getTimestamp();
    [$token, $pub] = mintLicense($now, $now, $now + 3600, ['feature.sso' => ['enabled' => true]]);

    $license = (new Ed25519LicenseVerifier($pub))->verify($token);

    expect($license->plan)->toBe('enterprise')
        ->and($license->grants('feature.sso'))->toBeTrue()
        ->and($license->entitlementValues()['feature.sso']->source)->toBe(EntitlementSource::License);
});

it('rejects a tampered payload', function (): void {
    $now = Carbon::now()->getTimestamp();
    [$token, $pub] = mintLicense($now, $now, $now + 3600);

    $parts = explode('.', $token);
    $parts[1] = strrev($parts[1]);

    expect(fn () => (new Ed25519LicenseVerifier($pub))->verify(implode('.', $parts)))
        ->toThrow(LicenseException::class);
});

it('rejects a token signed by a different key', function (): void {
    $now = Carbon::now()->getTimestamp();
    [$token] = mintLicense($now, $now, $now + 3600);
    $otherPub = sodium_crypto_sign_publickey(sodium_crypto_sign_keypair());

    expect(fn () => (new Ed25519LicenseVerifier($otherPub))->verify($token))
        ->toThrow(LicenseException::class);
});

it('rejects an expired license', function (): void {
    $now = Carbon::now()->getTimestamp();
    [$token, $pub] = mintLicense($now - 7200, $now - 7200, $now - 3600);

    expect(fn () => (new Ed25519LicenseVerifier($pub))->verify($token))
        ->toThrow(LicenseException::class);
});

it('rejects a not-yet-valid license', function (): void {
    $now = Carbon::now()->getTimestamp();
    [$token, $pub] = mintLicense($now + 3600, $now + 3600, $now + 7200);

    expect(fn () => (new Ed25519LicenseVerifier($pub))->verify($token))
        ->toThrow(LicenseException::class);
});

it('overlays license grants onto the entitlement reader, deployment-wide', function (): void {
    $this->installLicense(['feature.sso' => ['enabled' => true]]);

    $reader = app(EntitlementReader::class);

    expect($reader->get('org_anything', 'feature.sso')?->bool())->toBeTrue()
        ->and($reader->get('org_anything', 'feature.sso')?->source)->toBe(EntitlementSource::License)
        ->and(app(LicenseState::class)->isLicensed())->toBeTrue();
});

it('is the free tier with no license (base entitlements only)', function (): void {
    expect(app(LicenseState::class)->isLicensed())->toBeFalse()
        ->and(app(EntitlementReader::class)->get('org_x', 'feature.sso'))->toBeNull();
});

it('ignores an invalid configured license and stays free-tier', function (): void {
    config()->set('cbox-id.license.public_key', base64_encode(sodium_crypto_sign_publickey(sodium_crypto_sign_keypair())));
    config()->set('cbox-id.license.key', 'CBXLIC1.not-a-real.token');

    app()->forgetInstance(LicenseState::class);
    app()->forgetInstance(LicenseAwareEntitlements::class);
    app()->forgetInstance(EntitlementReader::class);

    expect(app(LicenseState::class)->isLicensed())->toBeFalse()
        ->and(app(EntitlementReader::class)->get('org_x', 'feature.sso'))->toBeNull();
});

it('honours a domain-bound license only on the matching host', function (): void {
    config()->set('cbox-id.issuer', 'https://id.acme.com');
    $this->installLicense(['feature.sso' => ['enabled' => true]], ['domains' => ['id.acme.com']]);
    expect(app(LicenseState::class)->isLicensed())->toBeTrue();

    config()->set('cbox-id.issuer', 'https://id.evil.com');
    $this->installLicense(['feature.sso' => ['enabled' => true]], ['domains' => ['id.acme.com']]);
    expect(app(LicenseState::class)->isLicensed())->toBeFalse();
});
