<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\PasswordReset;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Exceptions\InvalidPasswordReset;
use Cbox\Id\Identity\Models\PasswordResetToken;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('issues a hashed single-use token only for a real account', function (): void {
    app(Subjects::class)->create('sam@acme.test', 'Sam', 'old-password-123');
    $reset = app(PasswordReset::class);

    $token = $reset->request('sam@acme.test');

    expect($token)->toStartWith('pwr_')
        ->and(PasswordResetToken::query()->firstOrFail()->token_hash)->not->toBe($token);
});

it('does not reveal whether an account exists (no token, no row for unknown email)', function (): void {
    $token = app(PasswordReset::class)->request('nobody@acme.test');

    expect($token)->toBeNull()
        ->and(PasswordResetToken::query()->count())->toBe(0);
});

it('resets the password and revokes every existing session', function (): void {
    $subjects = app(Subjects::class);
    $subject = $subjects->create('sam@acme.test', 'Sam', 'old-password-123');
    $sessions = app(SessionManager::class);
    $live = $sessions->start($subject->id, null, ['pwd']);

    $token = app(PasswordReset::class)->request('sam@acme.test');
    app(PasswordReset::class)->reset((string) $token, 'brand-new-password-456');

    expect($subjects->verifyPassword($subject->id, 'brand-new-password-456'))->toBeTrue()
        ->and($subjects->verifyPassword($subject->id, 'old-password-123'))->toBeFalse()
        // A reset kills existing sessions so a thief can't ride one past the change.
        ->and($sessions->active($live->id))->toBeNull();
});

it('rejects an unknown, expired or reused token', function (): void {
    $subjects = app(Subjects::class);
    $subjects->create('sam@acme.test', 'Sam', 'old-password-123');
    $reset = app(PasswordReset::class);

    expect(fn () => $reset->reset('pwr_nonexistent', 'x-new-password-000'))
        ->toThrow(InvalidPasswordReset::class);

    // Reuse: a consumed token cannot reset again.
    $token = (string) $reset->request('sam@acme.test');
    $reset->reset($token, 'first-new-password-1');
    expect(fn () => $reset->reset($token, 'second-attempt-pw-2'))
        ->toThrow(InvalidPasswordReset::class);

    // Expiry.
    $expired = (string) $reset->request('sam@acme.test');
    PasswordResetToken::query()->latest('id')->first()?->forceFill(['expires_at' => now()->subMinute()])->save();
    expect(fn () => $reset->reset($expired, 'too-late-password-3'))
        ->toThrow(InvalidPasswordReset::class);
});
