<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\MagicLink;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\UserDirectory;
use Cbox\Id\Identity\Exceptions\InvalidMagicLink;
use Cbox\Id\Identity\Models\MagicLinkToken;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('issues a hashed single-use token', function (): void {
    $token = app(MagicLink::class)->request('sam@acme.test');

    expect($token)->toStartWith('ml_')
        ->and(MagicLinkToken::query()->firstOrFail()->token_hash)->not->toBe($token);
});

it('redeems a token into a session, provisioning the user', function (): void {
    $magic = app(MagicLink::class);
    $token = $magic->request('sam@acme.test');

    $session = $magic->redeem($token);

    expect($session->amr)->toBe(['magic_link'])
        ->and(app(UserDirectory::class)->findByEmail('sam@acme.test'))->not->toBeNull()
        ->and(app(SessionManager::class)->active($session->id))->not->toBeNull();
});

it('reuses an existing user', function (): void {
    $existing = app(UserDirectory::class)->create('sam@acme.test', 'Sam');
    $magic = app(MagicLink::class);

    $session = $magic->redeem($magic->request('sam@acme.test'));

    expect($session->user_id)->toBe($existing->id);
});

it('rejects a token that was already used', function (): void {
    $magic = app(MagicLink::class);
    $token = $magic->request('sam@acme.test');
    $magic->redeem($token);

    expect(fn () => $magic->redeem($token))->toThrow(InvalidMagicLink::class);
});

it('rejects an expired token', function (): void {
    MagicLinkToken::query()->create([
        'email' => 'sam@acme.test',
        'token_hash' => hash('sha256', 'ml_expired'),
        'expires_at' => now()->subMinute(),
    ]);

    expect(fn () => app(MagicLink::class)->redeem('ml_expired'))->toThrow(InvalidMagicLink::class);
});

it('rejects an unknown token', function (): void {
    expect(fn () => app(MagicLink::class)->redeem('ml_nope'))->toThrow(InvalidMagicLink::class);
});
