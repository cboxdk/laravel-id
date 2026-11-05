<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Identity\Contracts\TotpDevices;
use Cbox\Id\Identity\Exceptions\TotpDeviceRefused;
use Cbox\Id\Identity\Models\MfaFactor;
use Cbox\Id\Kernel\Crypto\TotpAuthenticator;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('keeps three apps independent, including replay protection and recovery codes', function (): void {
    $devices = app(TotpDevices::class);
    $mfa = app(Mfa::class);
    $totp = app(TotpAuthenticator::class);
    $recovery = $mfa->generateRecoveryCodes('alice');
    $apps = [];
    foreach (['Password manager', 'Phone', 'Backup phone'] as $name) {
        $app = $devices->enrollDevice('alice', 'alice@example.test', $name);
        expect($devices->confirmDevice('alice', $app->id, $totp->codeAt($app->secret, time() - 30)))->toBeTrue();
        $apps[] = $app;
    }
    expect(array_unique(array_column($apps, 'secret')))->toHaveCount(3)
        ->and($devices->devices('alice'))->toHaveCount(3)
        ->and($mfa->remainingRecoveryCodes('alice'))->toBe(10);
    foreach ($apps as $app) {
        $code = $totp->codeAt($app->secret, time());
        expect($mfa->verifyTotp('alice', $code))->toBeTrue()
            ->and($mfa->verifyTotp('alice', $code))->toBeFalse();
    }
    expect($mfa->verifyRecoveryCode('alice', $recovery[0]))->toBeTrue();
});

it('preserves a legacy credential when adding, renaming, cancelling and removing another app', function (): void {
    $devices = app(TotpDevices::class);
    $mfa = app(Mfa::class);
    $totp = app(TotpAuthenticator::class);
    $old = $mfa->enrollTotp('alice', 'alice@example.test');
    $mfa->confirmTotp('alice', $totp->codeAt($old->secret, time() - 30));
    $original = MfaFactor::query()->firstOrFail()->secret_encrypted;
    $next = $devices->enrollDevice('alice', 'alice@example.test', 'New app');
    expect($devices->devices('alice'))->toHaveCount(1)
        ->and($mfa->hasConfirmedTotp('alice'))->toBeTrue()
        ->and($mfa->verifyTotp('alice', $totp->codeAt($next->secret, time())))->toBeFalse();
    expect($devices->removeDevice('alice', $next->id))->toBeTrue();
    $next = $devices->enrollDevice('alice', 'alice@example.test', 'New app');
    $devices->confirmDevice('alice', $next->id, $totp->codeAt($next->secret, time() - 30));
    expect($devices->renameDevice('alice', $next->id, '  Spare phone  '))->toBeTrue()
        ->and(MfaFactor::query()->findOrFail($next->id)->name)->toBe('Spare phone')
        ->and($devices->removeDevice('alice', $next->id))->toBeTrue()
        ->and($mfa->verifyTotp('alice', $totp->codeAt($next->secret, time())))->toBeFalse()
        ->and(MfaFactor::query()->firstOrFail()->secret_encrypted)->toBe($original)
        ->and($mfa->verifyTotp('alice', $totp->codeAt($old->secret, time())))->toBeTrue();
    expect(fn () => $mfa->enrollTotp('alice', 'alice@example.test'))->toThrow(TotpDeviceRefused::class, 'already_enrolled');
});

it('refuses to remove the last confirmed app even when another enrolment is pending', function (): void {
    $devices = app(TotpDevices::class);
    $app = $devices->enrollDevice('alice', 'alice@example.test', 'Phone');
    $devices->confirmDevice('alice', $app->id, app(TotpAuthenticator::class)->codeAt($app->secret, time()));
    $devices->enrollDevice('alice', 'alice@example.test', 'Pending');
    expect(fn () => $devices->removeDevice('alice', $app->id))->toThrow(TotpDeviceRefused::class, 'last_device');
    expect($devices->devices('alice'))->toHaveCount(1);
});

it('scopes every operation to its owner and environment', function (): void {
    $devices = app(TotpDevices::class);
    $app = $devices->enrollDevice('alice', 'alice@example.test', 'Phone');
    $code = app(TotpAuthenticator::class)->codeAt($app->secret, time());
    expect($devices->confirmDevice('bob', $app->id, $code))->toBeFalse()
        ->and($devices->removeDevice('bob', $app->id))->toBeFalse();
    $this->actingAsEnvironment('env_other');
    expect($devices->confirmDevice('alice', $app->id, $code))->toBeFalse()
        ->and($devices->removeDevice('alice', $app->id))->toBeFalse();
    $this->actingAsEnvironment('env_test');
    expect($devices->confirmDevice('alice', $app->id, $code))->toBeTrue()
        ->and($devices->renameDevice('bob', $app->id, 'Stolen'))->toBeFalse()
        ->and($devices->devices('bob'))->toBe([]);
    $this->actingAsEnvironment('env_other');
    expect($devices->devices('alice'))->toBe([])
        ->and($devices->renameDevice('alice', $app->id, 'Stolen'))->toBeFalse()
        ->and(app(Mfa::class)->verifyTotp('alice', $code))->toBeFalse();
});

it('confirms exactly once and expires abandoned enrolments after ten minutes', function (): void {
    $devices = app(TotpDevices::class);
    $totp = app(TotpAuthenticator::class);
    $app = $devices->enrollDevice('alice', 'alice@example.test', 'Phone');
    expect($devices->confirmDevice('alice', $app->id, 'invalid'))->toBeFalse();
    $this->travel(11)->minutes();
    expect($devices->confirmDevice('alice', $app->id, $totp->codeAt($app->secret, time())))->toBeFalse();
    $fresh = $devices->enrollDevice('alice', 'alice@example.test', 'Phone');
    expect(MfaFactor::query()->find($app->id))->toBeNull()
        ->and($devices->confirmDevice('alice', $fresh->id, $totp->codeAt($fresh->secret, time())))->toBeTrue()
        ->and($devices->confirmDevice('alice', $fresh->id, $totp->codeAt($fresh->secret, time())))->toBeFalse();
});

it('bounds both pending and confirmed credentials to ten slots', function (): void {
    $devices = app(TotpDevices::class);
    for ($i = 0; $i < 10; $i++) {
        $devices->enrollDevice('alice', 'alice@example.test', 'App '.$i);
    }
    expect(fn () => $devices->enrollDevice('alice', 'alice@example.test', 'Eleventh'))
        ->toThrow(TotpDeviceRefused::class, 'limit_reached');
    $this->travel(11)->minutes();
    $devices->enrollDevice('alice', 'alice@example.test', 'Fresh');
    expect(MfaFactor::query()->count())->toBe(1);
});

it('rejects empty, oversized and control-character labels', function (string $name): void {
    expect(fn () => app(TotpDevices::class)->enrollDevice('alice', 'alice@example.test', $name))
        ->toThrow(TotpDeviceRefused::class, 'invalid_name');
})->with(['   ', str_repeat('x', 121), "My\nphone", "My\x00phone"]);

it('consumes colliding codes across all credentials rather than admitting the same digits twice', function (): void {
    $devices = app(TotpDevices::class);
    $first = $devices->enrollDevice('alice', 'alice@example.test', 'Phone');
    $second = $devices->enrollDevice('alice', 'alice@example.test', 'Copied key');
    $source = MfaFactor::query()->findOrFail($first->id);
    MfaFactor::query()->whereKey([$first->id, $second->id])->update([
        'secret_encrypted' => $source->secret_encrypted, 'confirmed_at' => now(),
    ]);
    $code = app(TotpAuthenticator::class)->codeAt($first->secret, time());
    expect(app(Mfa::class)->verifyTotp('alice', $code))->toBeTrue()
        ->and(app(Mfa::class)->verifyTotp('alice', $code))->toBeFalse()
        ->and(MfaFactor::query()->whereNull('last_used_step')->count())->toBe(0);
});

it('encodes the same issuer in the QR label and query using RFC 3986', function (): void {
    $uri = app(TotpAuthenticator::class)->provisioningUri('ABC', 'alice+test@example.test', 'Cbox ID');
    expect($uri)->toStartWith('otpauth://totp/Cbox%20ID%3Aalice%2Btest%40example.test?')
        ->toContain('issuer=Cbox%20ID')->not->toContain('+');
});

it('preserves the singleton SMS slot at the database boundary', function (): void {
    MfaFactor::query()->create(['user_id' => 'alice', 'type' => 'sms', 'secret_encrypted' => 'sealed']);
    expect(fn () => MfaFactor::query()->create(['user_id' => 'alice', 'type' => 'sms', 'secret_encrypted' => 'other']))
        ->toThrow(UniqueConstraintViolationException::class);
});

it('does not roll back the schema by discarding additional credentials', function (): void {
    $devices = app(TotpDevices::class);
    $devices->enrollDevice('alice', 'alice@example.test', 'Phone');
    $devices->enrollDevice('alice', 'alice@example.test', 'Backup');
    $migration = require __DIR__.'/../../../database/migrations/2026_11_05_000200_add_named_totp_devices.php';
    expect(fn () => $migration->down())->toThrow(RuntimeException::class, 'Cannot roll back')
        ->and(MfaFactor::query()->count())->toBe(2);
});
