<?php

declare(strict_types=1);

use Cbox\Id\Identity\Models\User;

it('merges the package config so cbox-id.* resolves in a host app', function (): void {
    // Defaults come from config/cbox-id.php via mergeConfigFrom in the provider.
    expect(config('cbox-id.models.user'))->toBe(User::class)
        ->and(config()->has('cbox-id.issuer'))->toBeTrue()
        ->and(config()->has('cbox-id.webauthn.rp_id'))->toBeTrue()
        ->and(config()->has('cbox-id.crypto.key'))->toBeTrue();
});
