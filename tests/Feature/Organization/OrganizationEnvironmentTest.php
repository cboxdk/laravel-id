<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Organization\Models\Organization;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * @group isolation
 *
 * The organization is the anchor of the tenancy tree, and it is now itself
 * environment-owned: an org (and its whole closure subtree) lives in exactly one
 * environment and is invisible from any other.
 */
it('scopes organizations to their environment', function (): void {
    $a = $this->runAsEnvironment('env_a', fn () => Organization::create(['name' => 'Acme', 'slug' => 'acme']));
    $this->runAsEnvironment('env_b', fn () => Organization::create(['name' => 'Globex', 'slug' => 'globex']));

    $this->actingAsEnvironment('env_a');
    expect(Organization::pluck('slug')->all())->toBe(['acme'])
        ->and(Organization::find($a->id)?->slug)->toBe('acme');

    // The env_b org is unreachable from env_a, even by primary key.
    $bId = $this->runAsEnvironment('env_b', fn () => Organization::where('slug', 'globex')->value('id'));
    expect(Organization::find($bId))->toBeNull();
});

it('auto-stamps the environment on a new organization', function (): void {
    $org = $this->runAsEnvironment('env_x', fn () => Organization::create(['name' => 'X', 'slug' => 'x-co']));

    expect($org->environment_id)->toBe('env_x');
});

it('denies organization reads when no environment is set', function (): void {
    $this->runAsEnvironment('env_a', fn () => Organization::create(['name' => 'Acme', 'slug' => 'acme2']));

    $this->forgetEnvironment();
    expect(Organization::count())->toBe(0);
});
