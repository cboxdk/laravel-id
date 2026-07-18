<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Platform\Contracts\EnvironmentAdminHandoff;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('mints and verifies a handoff, binding the account member to the environment', function (): void {
    $handoff = app(EnvironmentAdminHandoff::class);

    $token = $handoff->mint('acct_member_1', 'env_prod');
    $grant = $handoff->verify($token);

    expect($grant)->not->toBeNull()
        ->and($grant->accountMemberId)->toBe('acct_member_1')
        ->and($grant->environmentId)->toBe('env_prod');
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
