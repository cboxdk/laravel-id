<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\Exceptions\CrossEnvironmentAccess;
use Cbox\Id\Kernel\Tenancy\Exceptions\EnvironmentMissing;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Tests\Fixtures\EnvThing;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

uses(InteractsWithTenancy::class);

/**
 * @group isolation
 *
 * Load-bearing proof of ENVIRONMENT isolation — the hard outer boundary above the
 * organization tenant. The critical invariant: the organization-level escape
 * hatch (withoutTenantScope) and roll-up NEVER cross an environment. A leak here
 * is worse than a cross-tenant leak: it crosses user pools, keys and issuers.
 */
beforeEach(function (): void {
    Schema::dropIfExists('env_things');
    Schema::create('env_things', function (Blueprint $table): void {
        $table->ulid('id')->primary();
        $table->string('environment_id')->index();
        $table->string('organization_id')->index();
        $table->string('name');
        $table->timestamps();
    });

    // Seed: env_a has 2 rows (across two orgs); env_b has 1 row.
    $seed = fn (string $env, string $org, string $name) => $this->runAsEnvironment(
        $env,
        fn () => $this->runAsTenant($org, fn () => EnvThing::create(['name' => $name])),
    );
    $seed('env_a', 'org_1', 'a1');
    $seed('env_a', 'org_2', 'a2');
    $seed('env_b', 'org_1', 'b1');
});

it('isolates reads across environments', function (): void {
    $this->actingAsEnvironment('env_a');
    $this->withoutTenantScope(function (): void {   // org wall down…
        expect(EnvThing::count())->toBe(2)          // …env wall still up: only env_a
            ->and(EnvThing::pluck('name')->all())->not->toContain('b1');
    });
});

it('denies all reads when no environment is set (deny by default)', function (): void {
    $this->forgetEnvironment();
    $this->actingAsTenant('org_1');

    expect(EnvThing::count())->toBe(0);
});

it('never crosses the environment even when the org scope is suspended', function (): void {
    $this->actingAsEnvironment('env_a');

    // Suspending the ORG dimension must not reveal env_b's row.
    $names = $this->withoutTenantScope(fn () => EnvThing::pluck('name')->all());

    expect($names)->toHaveCount(2)->toContain('a1', 'a2')->not->toContain('b1');
});

it('cannot reach another environment row by primary key', function (): void {
    $bId = $this->runAsEnvironment('env_b', fn () => EnvThing::withoutGlobalScopes()->where('name', 'b1')->value('id'));

    $this->actingAsEnvironment('env_a');
    expect(EnvThing::find($bId))->toBeNull();
});

it('auto-fills the environment key on create', function (): void {
    $this->actingAsEnvironment('env_a');
    $thing = $this->runAsTenant('org_1', fn () => EnvThing::create(['name' => 'fresh']));

    expect($thing->environment_id)->toBe('env_a');
});

it('forbids persisting a row into another environment', function (): void {
    $this->actingAsEnvironment('env_a');

    $thing = new EnvThing(['name' => 'x', 'environment_id' => 'env_b', 'organization_id' => 'org_1']);

    expect(fn () => $thing->save())->toThrow(CrossEnvironmentAccess::class);
});

it('sees every environment only when the environment scope is explicitly suspended', function (): void {
    // Both walls are orthogonal: to see across environments AND organizations the
    // provisioning path must suspend both. Suspending only the org scope (above)
    // never reveals another environment.
    $total = $this->withoutEnvironmentScope(fn () => $this->withoutTenantScope(fn () => EnvThing::count()));

    expect($total)->toBe(3);
});

it('requireEnvironment throws when none is set', function (): void {
    $this->forgetEnvironment();

    expect(fn () => app(EnvironmentContext::class)->requireEnvironment())
        ->toThrow(EnvironmentMissing::class);
});

it('reads the current environment after the scoped context is flushed (queue-worker safety)', function (): void {
    // EnvironmentContext is a `scoped` binding — a queue worker gets a fresh one per
    // job. The global scope is registered once at model-boot, so it must resolve the
    // context PER QUERY, never capture the boot-time instance. This reproduces a
    // worker processing a second job: flush the scoped instances, act as a DIFFERENT
    // environment, and confirm the scope follows the NEW context — not the stale one.
    // Drop only the ORG wall so this exercises the ENVIRONMENT scope in isolation.
    $this->actingAsEnvironment('env_a');
    expect($this->withoutTenantScope(fn () => EnvThing::pluck('name')->all()))
        ->toContain('a1'); // boots the scope under env_a

    // Simulate the between-jobs container reset a queue worker performs.
    $this->app->forgetScopedInstances();

    // The next "job" acts as env_b on the freshly-resolved context instance.
    $this->actingAsEnvironment('env_b');

    // The scope must see env_b now. A captured stale instance would still read env_a
    // and leak a1/a2 into this env_b-scoped query.
    expect($this->withoutTenantScope(fn () => EnvThing::pluck('name')->all()))
        ->toBe(['b1']);
});
