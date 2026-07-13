<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\EmailVerification;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Exceptions\InvalidEmailVerification;
use Cbox\Id\Identity\Models\EmailVerificationToken;
use Cbox\Id\Identity\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function unverifiedSubject(): string
{
    $subject = app(Subjects::class)->create('sam@acme.test', 'Sam');
    User::query()->whereKey($subject->id)->update(['email_verified_at' => null]);

    return $subject->id;
}

it('issues a hashed single-use verification token bound to the subject', function (): void {
    $id = unverifiedSubject();

    $token = app(EmailVerification::class)->issue($id, 'sam@acme.test');

    expect($token)->toStartWith('evf_')
        ->and(EmailVerificationToken::query()->firstOrFail())
        ->token_hash->not->toBe($token)
        ->user_id->toBe($id);
});

it('verifies the email and marks the subject verified', function (): void {
    $id = unverifiedSubject();
    $verification = app(EmailVerification::class);

    $returned = $verification->verify($verification->issue($id, 'sam@acme.test'));

    expect($returned)->toBe($id)
        ->and(User::query()->whereKey($id)->value('email_verified_at'))->not->toBeNull();
});

it('does not verify a stale token after the address changed', function (): void {
    $id = unverifiedSubject();
    $verification = app(EmailVerification::class);
    $token = $verification->issue($id, 'sam@acme.test');

    // The subject changes their address before clicking the old link.
    User::query()->whereKey($id)->update(['email' => 'moved@acme.test']);

    $verification->verify($token);

    // The stale confirmation is a no-op — the new address stays unverified.
    expect(User::query()->whereKey($id)->value('email_verified_at'))->toBeNull();
});

it('rejects an unknown, expired or reused token', function (): void {
    $id = unverifiedSubject();
    $verification = app(EmailVerification::class);

    expect(fn () => $verification->verify('evf_nope'))->toThrow(InvalidEmailVerification::class);

    $token = $verification->issue($id, 'sam@acme.test');
    $verification->verify($token);
    expect(fn () => $verification->verify($token))->toThrow(InvalidEmailVerification::class);

    $expired = $verification->issue($id, 'sam@acme.test');
    EmailVerificationToken::query()->latest('id')->first()?->forceFill(['expires_at' => now()->subMinute()])->save();
    expect(fn () => $verification->verify($expired))->toThrow(InvalidEmailVerification::class);
});
