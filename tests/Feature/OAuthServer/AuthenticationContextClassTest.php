<?php

declare(strict_types=1);

use Cbox\Id\Api\Support\ServerMetadata;
use Cbox\Id\OAuthServer\Enums\AuthenticationContextClass;
use Cbox\Id\OAuthServer\Enums\AuthMethod;
use Cbox\Id\OAuthServer\ValueObjects\AuthenticationEvent;
use Cbox\Id\OAuthServer\ValueObjects\AuthenticationRequirement;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * `acr` was derived AFTER the fact from whatever `amr` happened to contain, while
 * discovery advertised `acr_values_supported` that nothing read — so an RP gating
 * admin access on aal2 got a password-only user authorized and an aal1 id_token, with
 * no path to demand MFA. One enum now backs the advertisement, the /authorize gate and
 * the id_token claim, so they cannot drift.
 */
it('derives aal2 only from a genuine second factor', function (array $amr, string $expected): void {
    expect(AuthenticationContextClass::forAmr($amr)->value)->toBe($expected);
})->with([
    'password only' => [['pwd'], 'urn:cbox-id:aal1'],
    'sso only' => [['sso'], 'urn:cbox-id:aal1'],
    'nothing' => [[], 'urn:cbox-id:aal1'],
    'password + totp' => [['pwd', 'mfa'], 'urn:cbox-id:aal2'],
    'emailed otp' => [['pwd', 'otp'], 'urn:cbox-id:aal2'],
    'passkey' => [['passkey'], 'urn:cbox-id:aal2'],
    'webauthn' => [['webauthn'], 'urn:cbox-id:aal2'],
]);

it('treats aal1 as met by any session and aal2 as met only by a second factor', function (): void {
    expect(AuthenticationContextClass::Aal1->isSatisfiedBy(['pwd']))->toBeTrue()
        ->and(AuthenticationContextClass::Aal2->isSatisfiedBy(['pwd']))->toBeFalse()
        ->and(AuthenticationContextClass::Aal2->isSatisfiedBy(['pwd', 'mfa']))->toBeTrue();
});

it('reads the strongest level named in an acr_values request', function (?string $request, ?AuthenticationContextClass $expected): void {
    expect(AuthenticationContextClass::fromRequest($request))->toBe($expected);
})->with([
    'absent' => [null, null],
    'blank' => ['   ', null],
    'aal1' => ['urn:cbox-id:aal1', AuthenticationContextClass::Aal1],
    'aal2' => ['urn:cbox-id:aal2', AuthenticationContextClass::Aal2],
    'both, strongest wins' => ['urn:cbox-id:aal1 urn:cbox-id:aal2', AuthenticationContextClass::Aal2],
    // acr_values is an ordered list of ACCEPTABLE classes, so a value another IdP
    // understands is ignored rather than refused.
    'unknown only' => ['urn:example:loa3', null],
    'unknown alongside ours' => ['urn:example:loa3 urn:cbox-id:aal2', AuthenticationContextClass::Aal2],
]);

it('advertises exactly the classes the enum asserts', function (): void {
    expect(ServerMetadata::document()['acr_values_supported'])
        ->toBe(['urn:cbox-id:aal1', 'urn:cbox-id:aal2'])
        ->toBe(AuthenticationContextClass::values());
});

it('reaches the phishing-resistant class only with a user-verified passkey', function (array $amr, bool $expected): void {
    expect(AuthenticationContextClass::PhishingResistant->isSatisfiedBy($amr))->toBe($expected);
})->with([
    'passkey sign-in' => [AuthMethod::forPasskey(), true],
    'password, then a passkey step-up' => [['pwd', 'passkey', 'pop', 'mfa'], true],
    'passkey without user verification' => [AuthMethod::forPasskey(userVerified: false), false],
    'password + totp' => [AuthMethod::forSecondFactorCode(), false],
    'password + sms' => [AuthMethod::forSmsCode(), false],
    'emailed otp' => [['pwd', 'otp'], false],
    'recovery code' => [AuthMethod::forRecoveryCode(), false],
    'legacy webauthn string' => [['webauthn', 'mfa'], false],
    'password only' => [['pwd'], false],
    'nothing' => [[], false],
]);

it('ranks phishing-resistant above aal2 without changing the level forAmr reports', function (): void {
    $amr = AuthMethod::forPasskey();

    expect(AuthenticationContextClass::forAmr($amr))->toBe(AuthenticationContextClass::Aal2)
        ->and(AuthenticationContextClass::strongestFor($amr))->toBe(AuthenticationContextClass::PhishingResistant)
        ->and(AuthenticationContextClass::strongestFor(AuthMethod::forSecondFactorCode()))->toBe(AuthenticationContextClass::Aal2)
        ->and(AuthenticationContextClass::PhishingResistant->reaches(AuthenticationContextClass::Aal2))->toBeTrue()
        ->and(AuthenticationContextClass::Aal2->reaches(AuthenticationContextClass::PhishingResistant))->toBeFalse()
        ->and(AuthenticationContextClass::Aal2->reaches(AuthenticationContextClass::Aal1))->toBeTrue();
});

it('states phr in a token and in discovery only when the host turns it on', function (): void {
    $amr = AuthMethod::forPasskey();

    expect(AuthenticationContextClass::assertedFor($amr))->toBe(AuthenticationContextClass::Aal2)
        ->and(AuthenticationContextClass::fromRequest('urn:cbox-id:phr'))->toBeNull()
        ->and((new AuthenticationEvent(time(), $amr))->acr())->toBe(AuthenticationContextClass::Aal2);

    config(['cbox-id.oauth.acr.phishing_resistant' => true]);

    expect(AuthenticationContextClass::assertedFor($amr))->toBe(AuthenticationContextClass::PhishingResistant)
        ->and(AuthenticationContextClass::assertedFor(AuthMethod::forSecondFactorCode()))->toBe(AuthenticationContextClass::Aal2)
        ->and(AuthenticationContextClass::fromRequest('urn:cbox-id:aal2 urn:cbox-id:phr'))->toBe(AuthenticationContextClass::PhishingResistant)
        ->and(AuthenticationContextClass::values())->toBe(['urn:cbox-id:aal1', 'urn:cbox-id:aal2', 'urn:cbox-id:phr'])
        ->and((new AuthenticationEvent(time(), $amr))->acr())->toBe(AuthenticationContextClass::PhishingResistant);

    // A phr token meets an aal2 requirement; an aal2 token does not meet a phr one.
    expect(AuthenticationRequirement::of(AuthenticationContextClass::Aal2)->assess('urn:cbox-id:phr', time())->isSatisfied())->toBeTrue()
        ->and(AuthenticationRequirement::of(AuthenticationContextClass::PhishingResistant)->assess('urn:cbox-id:aal2', time())->isSatisfied())->toBeFalse();
});
