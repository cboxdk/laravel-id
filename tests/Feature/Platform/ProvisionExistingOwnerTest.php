<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Platform\PlatformRoot;
use Cbox\Id\Platform\TenantProvisioner;
use Cbox\Id\Platform\ValueObjects\TenantBlueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * Provisioning a customer whose owner ALREADY holds a Cbox ID attaches to that identity
 * rather than failing.
 *
 * `users` is unique on (environment_id, email), so an unconditional create makes this
 * impossible for anybody already in the root — including the operator running the
 * installer, whose address is also the first customer's owner. `cbox-id:install
 * --multi-tenant` failed outright on it. The account plane never met this: a member lived
 * in its own table, so the same person could be an operator and an owner without either row
 * knowing.
 */
it('attaches an existing subject as the owner rather than minting a second', function (): void {
    platformRootEnvironment();

    $existing = app(PlatformRoot::class)->run(
        fn () => app(Subjects::class)->create('shared@acme.test', 'Shared', 'a-strong-unbreached-passphrase'),
    );

    $result = app(TenantProvisioner::class)->provision(new TenantBlueprint(
        organizationName: 'Acme',
        ownerEmail: 'shared@acme.test',
        ownerName: 'Ignored',
        ownerPassword: 'a-different-passphrase',
    ));

    expect($result->owner->id)->toBe($existing->id)
        ->and($result->membership->user_id)->toBe($existing->id);

    // The blueprint's password did NOT overwrite theirs. Provisioning is not a password
    // reset, and letting it be one would hand anyone who can provision the credential of
    // anyone whose address they can guess.
    expect(app(PlatformRoot::class)->run(
        fn (): bool => app(Subjects::class)->verifyPassword($existing->id, 'a-strong-unbreached-passphrase'),
    ))->toBeTrue();
});
