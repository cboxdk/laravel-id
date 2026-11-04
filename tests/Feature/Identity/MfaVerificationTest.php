<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\AuthPolicies;
use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Identity\Contracts\MfaMandate;
use Cbox\Id\Identity\Contracts\MfaVerification;
use Cbox\Id\Identity\Enums\MfaRequirement;
use Cbox\Id\Identity\Models\WebAuthnCredential;
use Cbox\Id\Identity\ValueObjects\AuthPolicy;
use Cbox\Id\Kernel\Crypto\TotpAuthenticator;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\ValueObjects\AuthenticationEvent;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('separates completed passkey enrolment from verification of a password session', function (): void {
    $user = $this->makeUser();
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(mfa: MfaRequirement::Required));
    WebAuthnCredential::query()->create(['user_id' => $user->id, 'credential_id' => 'enrolled', 'public_key' => 'not-used', 'sign_count' => 0]);
    expect(app(MfaMandate::class)->requiresEnrolment($user->id))->toBeFalse()
        ->and(app(MfaVerification::class)->requiresVerification($user->id, ['pwd']))->toBeTrue()
        ->and(app(MfaVerification::class)->requiresVerification($user->id, ['magic_link']))->toBeTrue()
        ->and(app(MfaVerification::class)->requiresVerification($user->id, ['passkey', 'pop', 'mfa']))->toBeFalse();
});

it('requires the enrolled TOTP after a magic link even under optional MFA', function (): void {
    $user = $this->makeUser();
    $factor = app(Mfa::class)->enrollTotp($user->id, $user->email);
    app(Mfa::class)->confirmTotp($user->id, (new TotpAuthenticator)->codeAt($factor->secret, time()));
    expect(app(MfaVerification::class)->requiresVerification($user->id, ['magic_link']))->toBeTrue()
        ->and(app(MfaVerification::class)->requiresVerification($user->id, ['magic_link', 'otp', 'mfa']))->toBeFalse();
});

it('does not impose local factors on an upstream federated authentication', function (): void {
    $user = $this->makeUser();
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(mfa: MfaRequirement::Required));
    expect(app(MfaVerification::class)->requiresVerification($user->id, ['saml']))->toBeFalse();
});

it('refuses issuing an authenticated user token from a weak local event under required MFA', function (): void {
    $user = $this->makeUser();
    $client = $this->makeClient(['openid'])->client;
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(mfa: MfaRequirement::Required));
    $issuer = app(TokenIssuer::class);
    expect(fn () => $issuer->issueForAuthenticatedUser($client, $user->id, null, ['openid'], new AuthenticationEvent(time(), ['pwd'])))
        ->toThrow(InvalidGrant::class);
    expect($issuer->issueForAuthenticatedUser($client, $user->id, null, ['openid'], new AuthenticationEvent(time(), ['pwd', 'mfa']))->token)->not->toBeEmpty();
});
