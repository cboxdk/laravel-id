<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Platform\Contracts\EnvironmentAdminHandoff;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

it('verifies ACROSS environments — minted on the account plane, redeemed on the target env host', function (): void {
    $handoff = app(EnvironmentAdminHandoff::class);

    // Minted while the account plane's (root) environment is active…
    $token = $this->runAsEnvironment('env_platform_root', fn () => $handoff->mint('acct_member_1', 'env_tenant_x'));

    // …redeemed while the TARGET tenant environment is active. Env signing keys differ
    // between these contexts, so this only works because the handoff signs/verifies in
    // its own fixed platform scope.
    $grant = $this->runAsEnvironment('env_tenant_x', fn () => $handoff->verify($token));

    expect($grant)->not->toBeNull()
        ->and($grant->accountMemberId)->toBe('acct_member_1')
        ->and($grant->environmentId)->toBe('env_tenant_x');
});

it('mints and verifies a handoff, binding the account member to the environment', function (): void {
    $handoff = app(EnvironmentAdminHandoff::class);

    $token = $handoff->mint('acct_member_1', 'env_prod');
    $grant = $handoff->verify($token);

    expect($grant)->not->toBeNull()
        ->and($grant->accountMemberId)->toBe('acct_member_1')
        ->and($grant->environmentId)->toBe('env_prod');
});

it('is single-use — a replayed handoff is refused', function (): void {
    $handoff = app(EnvironmentAdminHandoff::class);
    $token = $handoff->mint('acct_member_1', 'env_prod');

    // First redemption wins…
    expect($handoff->verify($token))->not->toBeNull();

    // …and the very same token — e.g. lifted from the target host's access logs or
    // browser history while still inside its short TTL — is refused on replay.
    expect($handoff->verify($token))->toBeNull();
});

it('refuses a tampered token', function (): void {
    $handoff = app(EnvironmentAdminHandoff::class);
    $token = $handoff->mint('acct_member_1', 'env_prod');

    // Flip a character in the payload segment.
    [$h, $p, $s] = explode('.', $token);
    $p[5] = $p[5] === 'A' ? 'B' : 'A';

    expect($handoff->verify("{$h}.{$p}.{$s}"))->toBeNull();
});

it('refuses an expired handoff', function (): void {
    // A correctly-signed, correct-purpose handoff — but already past its expiry.
    // (firebase/php-jwt checks the real clock, so we sign a past `exp` directly.)
    $expired = app(TokenSigner::class)->sign([
        'sub' => 'acct_member_1',
        'env' => 'env_prod',
        'purpose' => 'cbox.env-admin-handoff',
        'exp' => time() - 10,
    ]);

    expect(app(EnvironmentAdminHandoff::class)->verify($expired))->toBeNull();
});

it('refuses a token that is not a handoff (wrong purpose) — no cross-use with OAuth tokens', function (): void {
    // A perfectly-valid platform-signed token, but minted for something else.
    $foreign = app(TokenSigner::class)->sign([
        'sub' => 'acct_member_1',
        'env' => 'env_prod',
        'exp' => time() + 300,
        // no `purpose`, or a different one — an access token, an id_token, etc.
    ]);

    expect(app(EnvironmentAdminHandoff::class)->verify($foreign))->toBeNull();
});

it('refuses garbage', function (): void {
    expect(app(EnvironmentAdminHandoff::class)->verify('not-a-jwt'))->toBeNull();
});
