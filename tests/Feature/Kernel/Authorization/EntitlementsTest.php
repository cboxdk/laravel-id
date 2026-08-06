<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;
use Cbox\Id\Kernel\Authorization\Contracts\EntitlementWriter;
use Cbox\Id\Kernel\Authorization\Enums\EnforcementMode;
use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Cbox\Id\Kernel\Authorization\Models\Entitlement;
use Cbox\Id\Kernel\Authorization\Models\EntitlementChange;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementInput;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('sets and reads a versioned entitlement with provenance', function (): void {
    $value = app(EntitlementWriter::class)->set(
        'org_a',
        new EntitlementInput('plan', ['tier' => 'pro']),
        EntitlementSource::Billing,
        'sub_1Pk9',
    );

    expect($value->version)->toBe(1)->and($value->string('tier'))->toBe('pro');

    $read = app(EntitlementReader::class)->get('org_a', 'plan');

    expect($read?->string('tier'))->toBe('pro')
        ->and($read?->source)->toBe(EntitlementSource::Billing);
});

it('increments version on update and appends history', function (): void {
    $writer = app(EntitlementWriter::class);
    $writer->set('org_a', new EntitlementInput('seats', ['limit' => 10]), EntitlementSource::Billing);
    $updated = $writer->set('org_a', new EntitlementInput('seats', ['limit' => 50]), EntitlementSource::Billing);

    // Entitlement models are tenant-owned, so count within the org's scope.
    expect($updated->version)->toBe(2)
        ->and($updated->int('limit'))->toBe(50)
        ->and($this->runAsTenant('org_a', fn () => Entitlement::query()->count()))->toBe(1)
        ->and($this->runAsTenant('org_a', fn () => EntitlementChange::query()->where('key', 'seats')->count()))->toBe(2);
});

it('revokes an entitlement and records the change', function (): void {
    $writer = app(EntitlementWriter::class);
    $writer->set('org_a', new EntitlementInput('feature.sso', ['enabled' => true]), EntitlementSource::Manual);
    $writer->revoke('org_a', 'feature.sso', EntitlementSource::Manual);

    expect(app(EntitlementReader::class)->get('org_a', 'feature.sso'))->toBeNull()
        ->and($this->runAsTenant('org_a', fn () => Entitlement::query()->count()))->toBe(0)
        ->and($this->runAsTenant('org_a', fn () => EntitlementChange::query()->where('change', 'revoke')->count()))->toBe(1);
});

it('reconciles against the authoritative set: upserts present, revokes absent', function (): void {
    $writer = app(EntitlementWriter::class);
    $writer->set('org_a', new EntitlementInput('stale', ['enabled' => true]), EntitlementSource::Billing);

    $writer->reconcile('org_a', [
        new EntitlementInput('plan', ['tier' => 'pro']),
        new EntitlementInput('seats', ['limit' => 25]),
    ], EntitlementSource::Billing);

    $reader = app(EntitlementReader::class);

    expect($reader->get('org_a', 'stale'))->toBeNull()
        ->and($reader->get('org_a', 'plan'))->not->toBeNull()
        ->and($reader->all('org_a'))->toHaveCount(2);
});

it('emits an event and records an audit entry on write', function (): void {
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();

    app(EntitlementWriter::class)->set('org_a', new EntitlementInput('plan', ['tier' => 'pro']), EntitlementSource::Billing);

    $events->assertEmitted('entitlement.updated', fn (DomainEvent $e): bool => $e->organizationId === 'org_a');
    $audit->assertRecorded('entitlement.set');
});

it('does not return an expired entitlement', function (): void {
    Entitlement::query()->create([
        'organization_id' => 'org_a',
        'key' => 'trial',
        'value' => ['enabled' => true],
        'mode' => EnforcementMode::Claims,
        'source' => EntitlementSource::System,
        'version' => 1,
        'effective_at' => now()->subDay(),
        'expires_at' => now()->subHour(),
    ]);

    expect(app(EntitlementReader::class)->get('org_a', 'trial'))->toBeNull();
});

it('binds entitlement models to the tenant (deny-by-default on a forgotten filter)', function (): void {
    app(EntitlementWriter::class)->set('org_a', new EntitlementInput('x', ['v' => 1]), EntitlementSource::Manual);

    // A raw query with NO tenant context returns nothing — a forgotten
    // organization_id filter can no longer leak another tenant's entitlements.
    expect(Entitlement::query()->count())->toBe(0)
        ->and($this->runAsTenant('org_a', fn () => Entitlement::query()->count()))->toBe(1)
        ->and($this->runAsTenant('org_b', fn () => Entitlement::query()->count()))->toBe(0);
});
