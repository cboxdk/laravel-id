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

it('treats an idle session as inactive once the idle window passes', function (): void {
    $sessions = app(SessionManager::class); // idle_minutes defaults to 30

    $stale = Session::query()->create([
        'user_id' => 'user_1',
        'amr' => [],
        'last_active_at' => now()->subMinutes(31),
        'expires_at' => now()->addHours(8), // absolute ttl not yet reached
    ]);

    expect($sessions->active($stale->id))->toBeNull();
});

it('slides the idle window forward on activity', function (): void {
    $sessions = app(SessionManager::class);

    $session = Session::query()->create([
        'user_id' => 'user_1',
        'amr' => [],
        'last_active_at' => now()->subMinutes(5), // past the touch throttle
        'expires_at' => now()->addHours(8),
    ]);

    expect($sessions->active($session->id)?->id)->toBe($session->id);

    // Accessing it refreshed last_active_at, so the idle clock restarts.
    expect($session->fresh()?->last_active_at?->diffInSeconds(now()))->toBeLessThan(5);
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
