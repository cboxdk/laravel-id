<?php

declare(strict_types=1);

use Cbox\Id\Federation\Contracts\OidcRelyingParty;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Support\FirstAuthorizationProfile;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

/**
 * SIGN IN WITH APPLE WAS OFFERED AND COULD NOT COMPLETE.
 *
 * Every piece existed: the catalogue entry, its three parameters, a tested ES256 minter,
 * and the two declarations that say how Apple differs — `secretKind: SignedJwt` and
 * `responseMode: 'form_post'`. Nothing read any of them. The token exchange sent
 * whatever string the administrator had been forced to paste into a "client secret"
 * field for a provider that issues none, and the authorization request never asked for
 * the response mode Apple switches to on its own, so the callback arrived as a POST at a
 * handler written for a GET.
 *
 * These tests exercise the two seams from the connection inwards, because that is where
 * both defects lived: not in the minter (which was correct and covered), but in nobody
 * calling it.
 */
beforeEach(fn () => config(['cbox-id.federation.verify_url' => false]));

/**
 * @return array{private: string, public: string}
 */
function appleSignInKeypair(): array
{
    $resource = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    openssl_pkey_export($resource, $private);
    $public = openssl_pkey_get_details($resource)['key'];

    return ['private' => $private, 'public' => $public];
}

/**
 * A connection shaped the way the console stores one for Apple: the Services ID as the
 * client id, the three key fields, and NO client secret — because Apple issues none.
 *
 * @return array{config: array<string, mixed>, public: string}
 */
function appleConnectionConfig(): array
{
    $keys = appleSignInKeypair();

    return [
        'config' => [
            'issuer' => 'https://appleid.apple.com',
            'client_id' => 'com.acme.service',
            'authorization_endpoint' => 'https://appleid.apple.com/auth/authorize',
            'token_endpoint' => 'https://appleid.apple.com/auth/token',
            'team_id' => 'TEAM123456',
            'key_id' => 'KEY1234567',
            'private_key' => $keys['private'],
        ],
        'public' => $keys['public'],
    ];
}

it('authenticates to the token endpoint with a secret it mints itself', function (): void {
    $setup = appleConnectionConfig();
    $connection = $this->makeConnection(
        $this->makeOrganization()->id,
        ConnectionType::Oidc,
        'Apple',
        $setup['config'],
        provider: 'apple',
    );

    Http::fake(['appleid.apple.com/auth/token' => Http::response(['id_token' => 'not-verified-here'])]);

    // The exchange throws on the unverifiable id_token — irrelevant: what is under test
    // is the REQUEST, and specifically that it went out with a credential at all. Before
    // this, `client_secret` was required from stored config that never had one and the
    // call was refused before a request was made.
    try {
        app(OidcRelyingParty::class)
            ->exchangeCode($connection, 'auth-code', 'https://id.acme.test/callback');
    } catch (Throwable) {
        // The id_token is a placeholder; the assertion below is about what we sent.
    }

    $sent = null;
    Http::assertSent(function ($request) use (&$sent): bool {
        $sent = $request->data();

        return true;
    });

    expect($sent['client_secret'] ?? null)->toBeString();

    // A REAL SIGNATURE CHECK against the public half of the key the administrator
    // registered with Apple — the only evidence that what we send is something Apple
    // would accept, rather than a string that merely looks like a JWT.
    $claims = (array) JWT::decode((string) $sent['client_secret'], new Key($setup['public'], 'ES256'));

    expect($claims['iss'])->toBe('TEAM123456')
        ->and($claims['sub'])->toBe('com.acme.service')
        ->and($claims['aud'])->toBe('https://appleid.apple.com');
});

it('asks Apple for the response mode Apple would have used anyway', function (): void {
    $setup = appleConnectionConfig();
    $connection = $this->makeConnection(
        $this->makeOrganization()->id,
        ConnectionType::Oidc,
        'Apple',
        $setup['config'],
        provider: 'apple',
    );

    $url = app(OidcRelyingParty::class)
        ->authorizeUrl($connection, 'https://id.acme.test/callback', 'state-1', 'nonce-1');

    expect($url)->toContain('response_mode=form_post');
});

/**
 * The declaration is per provider, so the ordinary case must stay ordinary: a connection
 * from a catalogue entry that declares no response mode — or no catalogue entry at all —
 * gets the default, and nothing is added to its authorization request.
 */
it('leaves the response mode alone for a provider that does not need one', function (): void {
    $connection = $this->makeConnection(
        $this->makeOrganization()->id,
        ConnectionType::Oidc,
        'Corp',
        [
            'issuer' => 'https://idp.corp',
            'client_id' => 'rp-client',
            'client_secret' => 'rp-secret',
            'authorization_endpoint' => 'https://idp.corp/authorize',
            'token_endpoint' => 'https://idp.corp/token',
        ],
    );

    $url = app(OidcRelyingParty::class)
        ->authorizeUrl($connection, 'https://id.acme.test/callback', 'state-1', 'nonce-1');

    expect($url)->not->toContain('response_mode');
});

/**
 * And a pasted secret still wins where there is one — the minting path is chosen by the
 * connection's own material, not by guessing from the provider name.
 */
it('still sends a pasted secret for a provider that issues one', function (): void {
    $connection = $this->makeConnection(
        $this->makeOrganization()->id,
        ConnectionType::Oidc,
        'Corp',
        [
            'issuer' => 'https://idp.corp',
            'client_id' => 'rp-client',
            'client_secret' => 'rp-secret',
            'token_endpoint' => 'https://idp.corp/token',
        ],
    );

    Http::fake(['idp.corp/token' => Http::response(['id_token' => 'x'])]);

    app(OidcRelyingParty::class)
        ->exchangeCode($connection, 'auth-code', 'https://id.acme.test/callback');

    Http::assertSent(fn ($request): bool => $request->data()['client_secret'] === 'rp-secret');
});

/**
 * APPLE SENDS THE NAME ONCE, AND WE WERE THROWING IT AWAY.
 *
 * `name` never appears in Apple's id_token. It arrives as a `user` form field on the
 * FIRST authorization and never again for that person — so a callback that read only
 * `code` and `state` created every Sign in with Apple account with a null name,
 * permanently. The only recovery is for the person to revoke the app in their Apple ID
 * settings and start over.
 */
it('keeps the name Apple sends exactly once, on the first authorization', function (): void {
    $setup = appleConnectionConfig();
    $connection = $this->makeConnection(
        $this->makeOrganization()->id,
        ConnectionType::Oidc,
        'Apple',
        $setup['config'],
        provider: 'apple',
    );

    $principal = new FederatedPrincipal(provider: 'oidc', subject: 'apple-sub-1', email: 'dana@privaterelay.appleid.com');

    $merged = app(FirstAuthorizationProfile::class)->merge(
        $connection,
        Request::create('/callback', 'POST', [
            'user' => json_encode(['name' => ['firstName' => 'Dana', 'lastName' => 'Reeves']]),
        ]),
        $principal,
    );

    expect($merged->name)->toBe('Dana Reeves');
});

/**
 * And it is a fallback, not an override: the field is unsigned, so a name the ASSERTION
 * carried always wins. Nothing about `user` is covered by a signature.
 */
it('never lets the unsigned form field replace a name the assertion carried', function (): void {
    $setup = appleConnectionConfig();
    $connection = $this->makeConnection(
        $this->makeOrganization()->id,
        ConnectionType::Oidc,
        'Apple',
        $setup['config'],
        provider: 'apple',
    );

    $principal = new FederatedPrincipal(provider: 'oidc', subject: 'apple-sub-2', name: 'From The Token');

    $merged = app(FirstAuthorizationProfile::class)->merge(
        $connection,
        Request::create('/callback', 'POST', [
            'user' => json_encode(['name' => ['firstName' => 'Injected', 'lastName' => 'Name']]),
        ]),
        $principal,
    );

    expect($merged->name)->toBe('From The Token');
});

/**
 * A provider that does not declare the behaviour gets nothing read from its callback
 * body — this is one catalogue entry's quirk, not a general channel for setting a name.
 */
it('ignores a user field from a provider that does not send one', function (): void {
    $connection = $this->makeConnection(
        $this->makeOrganization()->id,
        ConnectionType::Oidc,
        'Corp',
        ['issuer' => 'https://idp.corp', 'client_id' => 'rp', 'client_secret' => 's'],
        provider: 'google',
    );

    $merged = app(FirstAuthorizationProfile::class)->merge(
        $connection,
        Request::create('/callback', 'POST', [
            'user' => json_encode(['name' => ['firstName' => 'Should', 'lastName' => 'Not Apply']]),
        ]),
        new FederatedPrincipal(provider: 'oidc', subject: 'google-sub'),
    );

    expect($merged->name)->toBeNull();
});
