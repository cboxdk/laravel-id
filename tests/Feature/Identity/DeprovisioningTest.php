<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Passkeys;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Contracts\WebAuthnVerifier;
use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Identity\Exceptions\AccountInactive;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Identity\Testing\FakeWebAuthnVerifier;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Exceptions\InvalidTokenExchange;
use Cbox\Id\OAuthServer\Models\AccessToken;
use Cbox\Id\OAuthServer\TokenExchangeService;
use Cbox\Id\OAuthServer\ValueObjects\TokenExchangeRequest;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * DEPROVISIONING HAS TO DEPROVISION.
 *
 * Deactivation revoked refresh tokens and stopped there. Everything already minted stayed
 * good until it expired, and nothing on any other login path asked whether the person
 * still had an account — `UserStatus` appeared nowhere in the OAuth module, nowhere in
 * the passkey verifier, and nowhere in the SAML IdP. The exception that says so has
 * existed the whole time: AccountInactive's docblock reads "revoking existing sessions is
 * not enough if the login paths don't also refuse". Federation login applied it. The
 * others did not.
 *
 * The compounding part is token exchange: RFC 8693 took a live access token and minted a
 * fresh one, so "until it expires" renewed itself for as long as the holder kept asking.
 * A leaver's connected application never lost access at all.
 */
function deprovisionedSubject(string $email = 'leaver@acme.test'): string
{
    return app(Subjects::class)->create($email, 'The Leaver')->id;
}

it('stops an already-issued access token the moment the account is deactivated', function (): void {
    $subject = deprovisionedSubject();
    $client = $this->makeClient(['openid'])->client;
    $issued = app(TokenIssuer::class)->issueForUser($client, $subject, null, ['openid']);

    expect(app(TokenIntrospector::class)->introspect($issued->token)->active)->toBeTrue();

    app(Subjects::class)->deactivate($subject);

    expect(app(TokenIntrospector::class)->introspect($issued->token)->active)->toBeFalse();
})->group('security');

it('revokes the access-token rows, not only the refresh grants', function (): void {
    // Two mechanisms, and both have to hold: the row is revoked at deactivation, AND
    // introspection refuses a suspended subject. Either alone leaves a window — a token
    // minted between the two, or a row a future code path forgets to revoke.
    $subject = deprovisionedSubject();
    $client = $this->makeClient(['openid'])->client;
    app(TokenIssuer::class)->issueForUser($client, $subject, null, ['openid']);

    app(Subjects::class)->deactivate($subject);

    expect(AccessToken::query()->where('user_id', $subject)->whereNull('revoked_at')->count())->toBe(0);
})->group('security');

it('refuses to exchange a deactivated subject’s token for a fresh one', function (): void {
    // THE ONE THAT MADE IT PERMANENT. Without this the holder exchanges the dying token
    // for a live one, then exchanges that, for as long as they care to.
    $subject = deprovisionedSubject();
    $registered = $this->makeClient(['openid']);
    $issued = app(TokenIssuer::class)->issueForUser($registered->client, $subject, null, ['openid']);

    app(Subjects::class)->deactivate($subject);

    // THE MESSAGE, not just the class. With the liveness guard gone the exchange falls
    // through to intendedFor(), which throws the same class for a different reason — so a
    // test asserting only the class passes whether the guard is present or not. Mutation
    // caught exactly that in the first draft of this file.
    expect(fn () => app(TokenExchangeService::class)->exchange($registered->client, new TokenExchangeRequest(
        subjectToken: $issued->token,
        subjectTokenType: TokenExchangeRequest::ACCESS_TOKEN_TYPE,
    )))->toThrow(InvalidTokenExchange::class, 'The subject token is not active.');
})->group('security');

it('refuses a passkey belonging to a deactivated account', function (): void {
    // The credential nobody collects on the last day, because it lives in a laptop's
    // secure enclave rather than on a piece of paper.
    app()->instance(WebAuthnVerifier::class, new FakeWebAuthnVerifier(
        credentialId: 'cred_leaver',
        registrationSignCount: 1,
        assertionSignCount: 2,
    ));

    $subject = deprovisionedSubject('passkey-leaver@acme.test');
    app(Passkeys::class)->register($subject, 'challenge', '{}');

    expect(app(Passkeys::class)->authenticate('cred_leaver', 'challenge', '{}'))->toBe($subject);

    app(Subjects::class)->deactivate($subject);

    expect(fn () => app(Passkeys::class)->authenticate('cred_leaver', 'challenge', '{}'))
        ->toThrow(AccountInactive::class);
})->group('security');

it('leaves an active account entirely alone', function (): void {
    // The positive control. A guard that refuses everybody passes every test above and is
    // still broken.
    $subject = deprovisionedSubject('still-here@acme.test');
    $client = $this->makeClient(['openid'])->client;
    $issued = app(TokenIssuer::class)->issueForUser($client, $subject, null, ['openid']);

    expect(app(TokenIntrospector::class)->introspect($issued->token)->active)->toBeTrue();
})->group('security');

/*
 * AND THE EXCHANGE CHECKS FOR ITSELF, not by leaning on the revocation above.
 *
 * The two defences mask each other: deactivation revokes the access-token rows, so a
 * deactivated subject's token introspects inactive anyway and the exchange guard is never
 * the thing that fires. Mutation showed it — neutralising the exchange's own `active`
 * check left every deprovisioning test green.
 *
 * So this presents a token that is inactive for a DIFFERENT reason — an ordinary
 * revocation, the "sign out everywhere" button — while its subject is perfectly active.
 * Only the exchange's own check can refuse it.
 */
it('refuses to exchange a revoked token even though its owner is still active', function (): void {
    $subject = deprovisionedSubject('still-employed@acme.test');
    $registered = $this->makeClient(['openid']);
    $issued = app(TokenIssuer::class)->issueForUser($registered->client, $subject, null, ['openid']);

    app(TokenIntrospector::class)->revoke($issued->jti);

    expect(app(Subjects::class)->isActive($subject))->toBeTrue();

    expect(fn () => app(TokenExchangeService::class)->exchange($registered->client, new TokenExchangeRequest(
        subjectToken: $issued->token,
        subjectTokenType: TokenExchangeRequest::ACCESS_TOKEN_TYPE,
    )))->toThrow(InvalidTokenExchange::class, 'The subject token is not active.');
})->group('security');

/*
 * And introspection's own liveness check, isolated the same way: a subject suspended
 * WITHOUT going through deactivate(), so no row was revoked and the only thing that can
 * refuse the token is the check itself.
 */
it('refuses a token whose owner was suspended without their grants being revoked', function (): void {
    $subject = deprovisionedSubject('locked-out@acme.test');
    $client = $this->makeClient(['openid'])->client;
    $issued = app(TokenIssuer::class)->issueForUser($client, $subject, null, ['openid']);

    // Straight to the row: a lockout, a directory sync, any path that changes status
    // without calling deactivate(). The access-token row stays untouched, so the only
    // thing that can refuse this token is introspection's own liveness check.
    User::query()->whereKey($subject)->update(['status' => UserStatus::Locked]);

    expect(AccessToken::query()->where('user_id', $subject)->whereNull('revoked_at')->count())->toBe(1)
        ->and(app(TokenIntrospector::class)->introspect($issued->token)->active)->toBeFalse();
})->group('security');
