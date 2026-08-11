<?php

declare(strict_types=1);

use Cbox\Id\SamlIdp\Enums\AuthnContext;

/**
 * A SIGNED ASSERTION IS A STATEMENT, and a false one is worse than a vague one.
 *
 * `AuthnContextClassRef` was hardcoded to `Password`, so every assertion claimed a
 * password had been typed — including for people who signed in with a passkey and typed
 * nothing. Relying parties make decisions on that field: an SP configured to require a
 * password would have been satisfied by a sign-in that had none, and one auditing "how did
 * this person authenticate" was reading a constant.
 *
 * It also disagreed with ourselves. The OIDC side derives `acr` from the same `amr`, so
 * one session produced an id_token saying aal2 and a SAML assertion saying Password.
 */
it('never claims a password was used when none was', function (array $amr): void {
    expect(AuthnContext::forAmr($amr))->not->toBe(AuthnContext::Password);
})->with([
    'passkey only' => [['passkey']],
    'webauthn only' => [['webauthn']],
    'nothing recorded' => [[]],
]);

/**
 * SAML 2.0's class list predates WebAuthn by more than a decade. `Smartcard` and
 * `SoftwarePKI` are close enough to be tempting and both would be untrue; "unspecified"
 * says exactly what we know — this person authenticated, and the vocabulary has no word
 * for how.
 */
it('says unspecified for a passkey rather than inventing a class', function (): void {
    expect(AuthnContext::forAmr(['passkey']))->toBe(AuthnContext::Unspecified)
        ->and(AuthnContext::forAmr(['webauthn']))->toBe(AuthnContext::Unspecified);
});

/**
 * `Password` means a password with NO transport protection. Every sign-in here crosses
 * TLS, so the old value understated the protection even in the case it was closest to.
 */
it('says password-protected-transport for a password, not bare password', function (array $amr): void {
    expect(AuthnContext::forAmr($amr))->toBe(AuthnContext::PasswordProtectedTransport);
})->with([
    'password alone' => [['pwd']],
    'password and a second factor' => [['pwd', 'otp']],
    'password and a passkey as second factor' => [['pwd', 'webauthn']],
]);

/**
 * An empty `amr` — a caller that predates this parameter — must be vague rather than
 * wrong. That is the whole reason the default is not `Password`.
 */
it('is vague, never wrong, when the caller says nothing', function (): void {
    expect(AuthnContext::forAmr([]))->toBe(AuthnContext::Unspecified);
});
