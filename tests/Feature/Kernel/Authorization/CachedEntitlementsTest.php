<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;
use Cbox\Id\Kernel\Authorization\Contracts\EntitlementWriter;
use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementInput;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

it('reflects an entitlement change instantly on the next read (hot path)', function (): void {
    $writer = app(EntitlementWriter::class);
    $reader = app(EntitlementReader::class);

    $writer->set('org_x', new EntitlementInput('plan', ['tier' => 'free']), EntitlementSource::Billing);
    expect($reader->get('org_x', 'plan')?->string('tier'))->toBe('free');

    // A billing change — no token, no TTL to wait out.
    $writer->set('org_x', new EntitlementInput('plan', ['tier' => 'pro']), EntitlementSource::Billing);
    expect($reader->get('org_x', 'plan')?->string('tier'))->toBe('pro');
});

it('serves reads from cache and only refreshes when a write bumps the version', function (): void {
    $writer = app(EntitlementWriter::class);
    $reader = app(EntitlementReader::class);

    $writer->set('org_x', new EntitlementInput('seats', ['limit' => 10]), EntitlementSource::Billing);
    expect($reader->get('org_x', 'seats')?->int('limit'))->toBe(10); // now cached

    // Mutate the row behind the cache's back (raw, bypassing the tenant scope).
    DB::table('entitlements')->where('key', 'seats')->update(['value' => json_encode(['limit' => 999])]);

    // Still served from cache — reads don't hit the DB on every call.
    expect($reader->get('org_x', 'seats')?->int('limit'))->toBe(10);

    // Any write to the org bumps its version → the next read is fresh.
    $writer->set('org_x', new EntitlementInput('feature.sso', ['enabled' => true]), EntitlementSource::Billing);
    expect($reader->get('org_x', 'seats')?->int('limit'))->toBe(999);
});

it('isolates the cache per organization', function (): void {
    $writer = app(EntitlementWriter::class);
    $reader = app(EntitlementReader::class);

    $writer->set('org_a', new EntitlementInput('plan', ['tier' => 'pro']), EntitlementSource::Billing);
    $writer->set('org_b', new EntitlementInput('plan', ['tier' => 'free']), EntitlementSource::Billing);

    // A change to org_a must not disturb org_b's cached view.
    $writer->set('org_a', new EntitlementInput('plan', ['tier' => 'enterprise']), EntitlementSource::Billing);

    expect($reader->get('org_a', 'plan')?->string('tier'))->toBe('enterprise')
        ->and($reader->get('org_b', 'plan')?->string('tier'))->toBe('free');
});
