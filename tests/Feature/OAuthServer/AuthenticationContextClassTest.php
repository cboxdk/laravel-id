<?php

declare(strict_types=1);

use Cbox\Id\Api\Support\ServerMetadata;
use Cbox\Id\OAuthServer\Enums\AuthenticationContextClass;
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
