<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Contracts\RefreshTokens;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\Exceptions\InvalidTokenExchange;
use Cbox\Id\OAuthServer\TokenExchangeService;
use Cbox\Id\OAuthServer\ValueObjects\TokenExchangeRequest;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * A REFRESH TOKEN BELONGS TO THE CLIENT IT WAS ISSUED TO.
 *
 * Found by mutation, not by reading: deleting the `hash_equals($token->client_id,
 * $clientId)` check in RefreshTokenService left all 1805 tests green. The rotation
 * suite covered reuse detection, the grace window and DPoP continuity, and never once
 * presented a token as the wrong client — so the one guard standing between two clients'
 * grants was the one nothing constrained.
 *
 * What it costs when it goes: any client that comes into possession of another's refresh
 * token — a shared browser extension, a logging proxy, a token pasted into the wrong
 * config — rotates it into a grant of its own, for that user, indefinitely. The theft
 * detection would not fire, because rotating is exactly what a refresh token is for.
 */
it('refuses a refresh token presented by a client it was not issued to', function (): void {
    $mine = $this->makeClient(['openid'])->client;
    $theirs = $this->makeClient(['openid'])->client;

    $token = app(RefreshTokens::class)->issue($mine, 'user_1', null, ['openid']);

    expect(fn () => app(RefreshTokens::class)->rotate($theirs->client_id, $token))
        ->toThrow(InvalidGrant::class);
})->group('security');

it('still rotates for the client it was issued to', function (): void {
    // The positive control: a guard that refuses every rotation passes the test above.
    $mine = $this->makeClient(['openid'])->client;

    $token = app(RefreshTokens::class)->issue($mine, 'user_1', null, ['openid']);
    $grant = app(RefreshTokens::class)->rotate($mine->client_id, $token);

    expect($grant->refreshToken)->toBeString()->not->toBe($token);
})->group('security');

/*
 * And the family survives the refusal. A wrong-client presentation is a mistake or a
 * theft attempt against ONE grant; revoking the family would let any client that learns a
 * token id sign the real holder out, turning the defence into a denial of service.
 */
it('does not revoke the family when the wrong client presents the token', function (): void {
    $mine = $this->makeClient(['openid'])->client;
    $theirs = $this->makeClient(['openid'])->client;

    $token = app(RefreshTokens::class)->issue($mine, 'user_1', null, ['openid']);

    try {
        app(RefreshTokens::class)->rotate($theirs->client_id, $token);
    } catch (InvalidGrant) {
        // expected
    }

    expect(app(RefreshTokens::class)->rotate($mine->client_id, $token)->refreshToken)->toBeString();
})->group('security');

/*
 * RFC 8707: the `resource` a token is requested for must be an absolute URI with no
 * fragment. Both refusals were unconstrained — deleting either left the whole suite green
 * — and what they stop is a malformed `aud` landing in a signed token, where every
 * resource server downstream has to decide for itself what it means.
 */
it('refuses a resource that is not an absolute URI', function (string $resource): void {
    $registered = $this->makeClient(['openid']);
    $issued = app(TokenIssuer::class)->issueForUser($registered->client, 'user_1', null, ['openid']);

    expect(fn () => app(TokenExchangeService::class)->exchange($registered->client, new TokenExchangeRequest(
        subjectToken: $issued->token,
        subjectTokenType: TokenExchangeRequest::ACCESS_TOKEN_TYPE,
        resource: $resource,
    )))->toThrow(InvalidTokenExchange::class);
})->with([
    'relative' => '/api',
    'no scheme' => 'api.acme.test/v1',
    'a fragment, which never reaches the server it names' => 'https://api.acme.test/v1#frag',
    'not a URL at all' => 'https://',
    // Scheme and host present and no fragment, so the shape check above passes it —
    // this is the case that makes the second refusal earn its place.
    'a host no URL parser accepts' => 'https://exa mple.test/v1',
])->group('security');

it('accepts an ordinary resource indicator', function (): void {
    $registered = $this->makeClient(['openid']);
    $issued = app(TokenIssuer::class)->issueForUser($registered->client, 'user_1', null, ['openid']);

    $result = app(TokenExchangeService::class)->exchange($registered->client, new TokenExchangeRequest(
        subjectToken: $issued->token,
        subjectTokenType: TokenExchangeRequest::ACCESS_TOKEN_TYPE,
        resource: 'https://api.acme.test/v1',
    ));

    expect($result->token->token)->toBeString();
})->group('security');
