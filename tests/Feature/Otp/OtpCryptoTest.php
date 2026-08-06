<?php

declare(strict_types=1);

use Cbox\Id\Otp\Contracts\OtpHasher;
use Cbox\Id\Otp\Contracts\OtpService;
use Cbox\Id\Otp\KeyedOtpHasher;
use Cbox\Id\Otp\Models\OtpChallenge;
use Cbox\Id\Tests\Fixtures\CountingOtpHasher;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('never stores the plaintext code, only a keyed hash', function (): void {
    $channel = $this->fakeOtpChannel();
    $challenge = $this->issueOtp('login', 'frank@example.test');
    $code = (string) $channel->codeFor('frank@example.test');

    $stored = OtpChallenge::query()->whereKey($challenge->id)->firstOrFail();

    // The at-rest column is a 64-char hex HMAC, NOT the code.
    expect($stored->code_hash)->not->toBe($code)
        ->and($stored->code_hash)->toMatch('/^[0-9a-f]{64}$/')
        ->and($stored->getRawOriginal('code_hash'))->not->toContain($code);
});

it('keeps the code out of audit rows and out of the returned challenge', function (): void {
    $audit = $this->fakeAudit();
    $channel = $this->fakeOtpChannel();

    $challenge = $this->issueOtp('login', 'grace@example.test');
    $code = (string) $channel->codeFor('grace@example.test');

    $audit->assertRecorded('otp.issued');

    // No recorded audit event carries the code, anywhere in its context.
    foreach ($audit->recorded as $event) {
        expect(json_encode($event->context))->not->toContain($code);
    }

    // The caller-facing value object exposes no code either.
    expect(json_encode($challenge))->not->toContain($code);
});

it('performs the hash compare even on the miss path (no oracle)', function (): void {
    // Spy on the hasher so we can PROVE the compare runs, not just assert it.
    $spy = new CountingOtpHasher(new KeyedOtpHasher(random_bytes(32)));
    app()->instance(OtpHasher::class, $spy);
    app()->forgetInstance(OtpService::class);

    $this->fakeOtpChannel();

    // A never-issued challenge id: the service still runs a constant-time compare
    // against the DECOY and returns the uniform invalid result — no early return.
    $result = $this->verifyOtp('01OTPDOESNOTEXIST0000000000', '424242');

    expect($result->verified)->toBeFalse()
        ->and($spy->verifyCalls)->toBe(1)
        ->and($spy->verifiedAgainst)->toBe([$spy->decoy()]);
});
