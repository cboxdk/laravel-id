<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Contracts\TenantContext;
use Cbox\Id\Kernel\Tenancy\Exceptions\CrossTenantAccess;
use Cbox\Id\Kernel\Tenancy\Exceptions\TenantMissing;
use Cbox\Id\Kernel\Tenancy\GenericTenant;
use Cbox\Id\Tests\Fixtures\TenantThing;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * @group isolation
 *
 * These tests are the load-bearing proof of tenant isolation. If any of them
 * ever pass while a cross-tenant leak exists, the whole platform's security
 * guarantee is void. They are written to fail loudly on any leak.
 */
if (! function_exists('tenantCtx')) {
    function tenantCtx(): TenantContext
    {
        return app(TenantContext::class);
    }
}

beforeEach(function (): void {
    Schema::dropIfExists('tenant_things');
    Schema::create('tenant_things', function (Blueprint $table): void {
        $table->ulid('id')->primary();
        $table->string('organization_id')->index();
        $table->string('name');
        $table->timestamps();
    });
});

it('isolates reads across tenants', function (): void {
    tenantCtx()->runAs(new GenericTenant('org_a'), fn () => TenantThing::create(['name' => 'a1']));
    tenantCtx()->runAs(new GenericTenant('org_b'), fn () => TenantThing::create(['name' => 'b1']));

    tenantCtx()->runAs(new GenericTenant('org_a'), function (): void {
        expect(TenantThing::count())->toBe(1)
            ->and(TenantThing::sole()->name)->toBe('a1');
    });

    tenantCtx()->runAs(new GenericTenant('org_b'), function (): void {
        expect(TenantThing::count())->toBe(1)
            ->and(TenantThing::sole()->name)->toBe('b1');
    });
})->group('isolation');

it('denies all reads when no tenant is set (deny by default)', function (): void {
    tenantCtx()->runAs(new GenericTenant('org_a'), fn () => TenantThing::create(['name' => 'a1']));

    // No tenant in context: a leak would return the row; correct behaviour is zero.
    expect(TenantThing::count())->toBe(0)
        ->and(TenantThing::first())->toBeNull();
})->group('isolation');

it('cannot reach another tenant row by primary key', function (): void {
    $bId = tenantCtx()->runAs(new GenericTenant('org_b'), fn () => TenantThing::create(['name' => 'secret'])->id);

    tenantCtx()->runAs(new GenericTenant('org_a'), function () use ($bId): void {
        expect(TenantThing::find($bId))->toBeNull();
    });
})->group('isolation');

it('auto-fills the tenant key on create', function (): void {
    $thing = tenantCtx()->runAs(new GenericTenant('org_a'), fn () => TenantThing::create(['name' => 'x']));

    expect($thing->organization_id)->toBe('org_a');
})->group('isolation');

it('forbids persisting a row for another tenant', function (): void {
    tenantCtx()->runAs(new GenericTenant('org_a'), function (): void {
        $thing = new TenantThing(['name' => 'x']);
        $thing->organization_id = 'org_b';

        expect(fn () => $thing->save())->toThrow(CrossTenantAccess::class);
    });
})->group('isolation');

it('sees every tenant only when scoping is explicitly suspended', function (): void {
    tenantCtx()->runAs(new GenericTenant('org_a'), fn () => TenantThing::create(['name' => 'a1']));
    tenantCtx()->runAs(new GenericTenant('org_b'), fn () => TenantThing::create(['name' => 'b1']));

    $total = tenantCtx()->withoutScope(fn () => TenantThing::count());

    expect($total)->toBe(2);
})->group('isolation');

it('restores the previous tenant after runAs, even on exception', function (): void {
    $this->actingAsTenant('org_a');

    try {
        tenantCtx()->runAs(new GenericTenant('org_b'), function (): void {
            expect(tenantCtx()->current()?->tenantKey())->toBe('org_b');
            throw new RuntimeException('boom');
        });
    } catch (RuntimeException) {
        // swallow
    }

    expect(tenantCtx()->current()?->tenantKey())->toBe('org_a');
})->group('isolation');

it('requireTenant throws when no tenant is set', function (): void {
    $this->forgetTenant();

    expect(fn () => tenantCtx()->requireTenant())->toThrow(TenantMissing::class);
})->group('isolation');

it('reference-counts nested scope suspension', function (): void {
    $this->actingAsTenant('org_a');

    tenantCtx()->withoutScope(function (): void {
        tenantCtx()->withoutScope(function (): void {
            expect(tenantCtx()->isScopingSuspended())->toBeTrue();
        });
        // still suspended after the inner block exits
        expect(tenantCtx()->isScopingSuspended())->toBeTrue();
    });

    expect(tenantCtx()->isScopingSuspended())->toBeFalse();
})->group('isolation');

it('scopes reads to an explicit set of tenants (roll-up)', function (): void {
    tenantCtx()->runAs(new GenericTenant('org_a'), fn () => TenantThing::create(['name' => 'a1']));
    tenantCtx()->runAs(new GenericTenant('org_b'), fn () => TenantThing::create(['name' => 'b1']));
    tenantCtx()->runAs(new GenericTenant('org_c'), fn () => TenantThing::create(['name' => 'c1']));

    $names = tenantCtx()->scopedTo(['org_a', 'org_b'], fn () => TenantThing::query()->pluck('name')->all());

    expect($names)->toHaveCount(2)
        ->and($names)->toContain('a1', 'b1')
        ->and($names)->not->toContain('c1');
})->group('isolation');

it('denies all reads for an empty roll-up set (deny by default)', function (): void {
    tenantCtx()->runAs(new GenericTenant('org_a'), fn () => TenantThing::create(['name' => 'a1']));

    $count = tenantCtx()->scopedTo([], fn () => TenantThing::count());

    expect($count)->toBe(0);
})->group('isolation');

it('restores scope after a scopedTo block', function (): void {
    tenantCtx()->runAs(new GenericTenant('org_a'), fn () => TenantThing::create(['name' => 'a1']));
    tenantCtx()->runAs(new GenericTenant('org_b'), fn () => TenantThing::create(['name' => 'b1']));

    tenantCtx()->scopedTo(['org_a', 'org_b'], fn () => TenantThing::count());

    expect(tenantCtx()->activeScopeKeys())->toBeNull()
        ->and(TenantThing::count())->toBe(0); // back to deny-by-default (no tenant)
})->group('isolation');

it('uses the innermost set when scopedTo is nested', function (): void {
    tenantCtx()->runAs(new GenericTenant('org_a'), fn () => TenantThing::create(['name' => 'a1']));
    tenantCtx()->runAs(new GenericTenant('org_b'), fn () => TenantThing::create(['name' => 'b1']));

    $inner = tenantCtx()->scopedTo(['org_a', 'org_b'], fn () => tenantCtx()->scopedTo(['org_a'], fn () => TenantThing::count()));

    expect($inner)->toBe(1);
})->group('isolation');

it('suspending scope overrides a roll-up set', function (): void {
    tenantCtx()->runAs(new GenericTenant('org_a'), fn () => TenantThing::create(['name' => 'a1']));
    tenantCtx()->runAs(new GenericTenant('org_b'), fn () => TenantThing::create(['name' => 'b1']));

    $total = tenantCtx()->scopedTo(['org_a'], fn () => tenantCtx()->withoutScope(fn () => TenantThing::count()));

    expect($total)->toBe(2);
})->group('isolation');
