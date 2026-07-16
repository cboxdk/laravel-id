<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;
use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Cbox\Id\Licensing\LicenseAwareEntitlements;
use Cbox\Id\Licensing\LicenseState;
use Cbox\License\Capabilities;
use Cbox\License\Support\Ed25519KeyPair;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('overlays a license\'s grants onto the entitlement reader, deployment-wide', function (): void {
    $this->installLicense([Capabilities::SSO, Capabilities::SCIM]);

    $reader = app(EntitlementReader::class);

    // Deployment-wide: any org id sees the grant, sourced from the license.
    expect($reader->get('org_anything', Capabilities::SSO)?->bool())->toBeTrue()
        ->and($reader->get('org_anything', Capabilities::SSO)?->source)->toBe(EntitlementSource::License)
        ->and($reader->get('org_anything', Capabilities::SCIM)?->bool())->toBeTrue()
        ->and(app(LicenseState::class)->isLicensed())->toBeTrue();
});

it('is the free tier with no license (base entitlements only)', function (): void {
    expect(app(LicenseState::class)->isLicensed())->toBeFalse()
        ->and(app(EntitlementReader::class)->get('org_x', Capabilities::SSO))->toBeNull();
});

it('does not grant a capability the license omits', function (): void {
    $this->installLicense([Capabilities::SSO]);

    expect(app(EntitlementReader::class)->get('org_x', Capabilities::RISK_PLUS))->toBeNull();
});

it('ignores an invalid configured license and stays free-tier', function (): void {
    config()->set('cbox-id.license.public_key', Ed25519KeyPair::generate()['publicKey']);
    config()->set('cbox-id.license.key', 'not-a-real-token');

    app()->forgetInstance(LicenseState::class);
    app()->forgetInstance(LicenseAwareEntitlements::class);
    app()->forgetInstance(EntitlementReader::class);

    expect(app(LicenseState::class)->isLicensed())->toBeFalse()
        ->and(app(EntitlementReader::class)->get('org_x', Capabilities::SSO))->toBeNull();
});

it('locks features once a license is expired beyond grace', function (): void {
    $this->installLicense([Capabilities::SSO], ['expires' => '-1 hour']);

    expect(app(LicenseState::class)->isLicensed())->toBeFalse()
        ->and(app(EntitlementReader::class)->get('org_x', Capabilities::SSO))->toBeNull();
});

it('honours a domain-bound license only on the matching host', function (): void {
    config()->set('cbox-id.issuer', 'https://id.acme.com');
    $this->installLicense([Capabilities::SSO], ['domain' => 'id.acme.com']);
    expect(app(LicenseState::class)->isLicensed())->toBeTrue();

    config()->set('cbox-id.issuer', 'https://id.evil.com');
    $this->installLicense([Capabilities::SSO], ['domain' => 'id.acme.com']);
    expect(app(LicenseState::class)->isLicensed())->toBeFalse();
});
