<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Models\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('starts an active session and records how the user authenticated', function (): void {
    $sessions = app(SessionManager::class);
    $session = $sessions->start('user_1', 'org_a', ['pwd', 'mfa'], '1.2.3.4', 'agent');

    expect($sessions->active($session->id)?->id)->toBe($session->id)
        ->and($session->amr)->toBe(['pwd', 'mfa'])
        ->and($session->organization_id)->toBe('org_a');
});

it('treats an expired session as inactive', function (): void {
    $sessions = app(SessionManager::class);
    $expired = Session::query()->create([
        'user_id' => 'user_1',
        'amr' => [],
        'expires_at' => now()->subHour(),
    ]);

    expect($sessions->active($expired->id))->toBeNull();
});

it('revokes a single session', function (): void {
    $sessions = app(SessionManager::class);
    $session = $sessions->start('user_1', null, ['pwd']);

    $sessions->revoke($session->id);

    expect($sessions->active($session->id))->toBeNull();
});

it('revokes every session for a user (forced logout)', function (): void {
    $sessions = app(SessionManager::class);
    $a = $sessions->start('user_1', null, ['pwd']);
    $b = $sessions->start('user_1', null, ['pwd']);

    $sessions->revokeAllForUser('user_1');

    expect($sessions->active($a->id))->toBeNull()
        ->and($sessions->active($b->id))->toBeNull();
});
