<?php

declare(strict_types=1);

use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * @group isolation
 *
 * SCIM-provisioned directory resources are environment-owned: a directory user
 * synced in one environment never leaks into another — not by query, not by its
 * primary key.
 */
it('scopes directory users to their environment', function (): void {
    $user = $this->runAsEnvironment('env_a', fn () => DirectoryUser::create([
        'directory_id' => 'dir_1',
        'external_id' => 'ext-1',
        'resource' => ['userName' => 'alice'],
        'active' => true,
    ]));

    // Auto-stamped on create.
    expect($user->environment_id)->toBe('env_a');

    // Invisible from env_b — even by primary key.
    $this->runAsEnvironment('env_b', function () use ($user): void {
        expect(DirectoryUser::count())->toBe(0)
            ->and(DirectoryUser::where('external_id', 'ext-1')->exists())->toBeFalse()
            ->and(DirectoryUser::find($user->id))->toBeNull();
    });

    // Still reachable from its own environment.
    $this->runAsEnvironment('env_a', fn () => expect(DirectoryUser::find($user->id))->not->toBeNull());
})->group('isolation');
