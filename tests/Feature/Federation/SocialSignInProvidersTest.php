<?php

declare(strict_types=1);

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\OidcRelyingParty;
use Cbox\Id\Federation\Contracts\OidcTokenExchange;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Enums\FederationProtocol;
use Cbox\Id\Federation\Enums\TokenEndpointAuthMethod;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\OAuth2Client;
use Cbox\Id\Federation\OidcDiscovery;
use Cbox\Id\Federation\ProviderCatalog;
use Cbox\Id\Federation\ValueObjects\OAuth2ConnectionConfig;
use Cbox\Id\Federation\ValueObjects\ProviderTemplate;
use Cbox\Id\Identity\Models\IdentityLink;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class);

/*
 * LinkedIn, Bitbucket, Xero and Intuit, driven end to end through the same seams a real
 * sign-in uses: the catalogue entry → discovery (for the OIDC three) → the stored
 * connection → the callback. Every provider response is faked with the shape the
 * provider documents, and every id_token is signed by a freshly generated RSA key that
 * the faked JWKS publishes — so signature, issuer, audience and nonce are all checked
 * for real, not stubbed.
 *
 * The discovery documents are the providers' own, as fetched on 2026-10-08, trimmed to
 * the keys this package reads plus the ones whose presence or absence matters.
 */

beforeEach(fn () => config(['cbox-id.federation.verify_url' => false]));

/**
 * @return array{private: string, jwk: array<string, string>}
 */
function socialSigningKey(string $kid): array
{
    $resource = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    openssl_pkey_export($resource, $private);
    $rsa = openssl_pkey_get_details($resource)['rsa'];

    $b64url = static fn (string $bytes): string => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');

    return [
        'private' => $private,
        'jwk' => ['kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256', 'n' => $b64url($rsa['n']), 'e' => $b64url($rsa['e'])],
    ];
}

/**
 * @param  array<string, mixed>  $claims
 */
function socialIdToken(string $private, string $kid, array $claims): string
{
    $now = time();

    return JWT::encode([...$claims, 'iat' => $now, 'exp' => $now + 300], $private, 'RS256', $kid);
}

/**
 * The connection a console would save for a catalogue provider: discovery run against
 * the entry's own issuer and discovery URL, the result's config, plus the customer's
 * client credentials.
 */
function socialConnection(string $provider, string $organizationId, string $clientId = 'client-123', string $secret = 'secret-456'): Connection
{
    $template = ProviderCatalog::find($provider);
    expect($template)->toBeInstanceOf(ProviderTemplate::class);

    $discovered = app(OidcDiscovery::class)->fromIssuer((string) $template->issuerFor([]), $template->discoveryUrl);

    return test()->makeConnection(
        $organizationId,
        ConnectionType::Oidc,
        $template->name,
        [...$discovered->toConfig(), 'client_id' => $clientId, 'client_secret' => $secret],
        provider: $provider,
    );
}

function socialCallback(Connection $connection, string $nonce): TestResponse
{
    return test()->withSession(['oidc.'.$connection->id => ['state' => 'state-1', 'nonce' => $nonce]])
        ->get('/sso/oidc/'.$connection->id.'/callback?code=the-code&state=state-1');
}

/** @return array<string, string> the form body of the faked request */
function socialForm(Request $request): array
{
    parse_str($request->body(), $form);

    return array_map(static fn (mixed $v): string => is_string($v) ? $v : '', $form);
}

const LINKEDIN_DISCOVERY = [
    'issuer' => 'https://www.linkedin.com/oauth',
    'authorization_endpoint' => 'https://www.linkedin.com/oauth/v2/authorization',
    'token_endpoint' => 'https://www.linkedin.com/oauth/v2/accessToken',
    'userinfo_endpoint' => 'https://api.linkedin.com/v2/userinfo',
    'jwks_uri' => 'https://www.linkedin.com/oauth/openid/jwks',
    'response_types_supported' => ['code'],
    'subject_types_supported' => ['pairwise'],
    'id_token_signing_alg_values_supported' => ['RS256'],
    'scopes_supported' => ['openid', 'profile', 'email'],
];

const XERO_DISCOVERY = [
    'issuer' => 'https://identity.xero.com',
    'jwks_uri' => 'https://identity.xero.com/.well-known/openid-configuration/jwks',
    'authorization_endpoint' => 'https://login.xero.com/identity/connect/authorize',
    'token_endpoint' => 'https://identity.xero.com/connect/token',
    'userinfo_endpoint' => 'https://identity.xero.com/connect/userinfo',
    'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post'],
    'id_token_signing_alg_values_supported' => ['RS256'],
];

const INTUIT_DISCOVERY = [
    'issuer' => 'https://oauth.platform.intuit.com/op/v1',
    'authorization_endpoint' => 'https://appcenter.intuit.com/connect/oauth2',
    'token_endpoint' => 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer',
    'userinfo_endpoint' => 'https://accounts.platform.intuit.com/v1/openid_connect/userinfo',
    'jwks_uri' => 'https://oauth.platform.intuit.com/op/v1/jwks',
    'token_endpoint_auth_methods_supported' => ['client_secret_post', 'client_secret_basic'],
    'id_token_signing_alg_values_supported' => ['RS256'],
    'claims_supported' => ['aud', 'exp', 'iat', 'iss', 'realmid', 'sub'],
];

it('appends the four new providers without moving anyone already there', function (): void {
    // Keys are stored on connections and ordering is what a console renders, so the
    // existing eleven must stay exactly where they were.
    expect(ProviderCatalog::keys())->toBe([
        'google', 'microsoft', 'okta', 'auth0', 'keycloak', 'gitlab', 'slack', 'github', 'discord', 'apple', 'facebook',
        'linkedin', 'bitbucket', 'xero', 'intuit',
    ]);

    expect(ProviderCatalog::find('linkedin')?->protocol)->toBe(FederationProtocol::Oidc)
        ->and(ProviderCatalog::find('xero')?->protocol)->toBe(FederationProtocol::Oidc)
        ->and(ProviderCatalog::find('intuit')?->protocol)->toBe(FederationProtocol::Oidc)
        ->and(ProviderCatalog::find('bitbucket')?->protocol)->toBe(FederationProtocol::OAuth2);
});

it('resolves each OIDC entry to the issuer its provider publishes', function (): void {
    expect(ProviderCatalog::find('linkedin')?->issuerFor([]))->toBe('https://www.linkedin.com/oauth')
        ->and(ProviderCatalog::find('xero')?->issuerFor([]))->toBe('https://identity.xero.com')
        ->and(ProviderCatalog::find('intuit')?->issuerFor([]))->toBe('https://oauth.platform.intuit.com/op/v1');

    // Everyone but Intuit keeps the standard location; Intuit's is its documented one.
    expect(ProviderCatalog::find('linkedin')?->discoveryUrlFor([]))->toBe('https://www.linkedin.com/oauth/.well-known/openid-configuration')
        ->and(ProviderCatalog::find('intuit')?->discoveryUrlFor([]))->toBe('https://developer.api.intuit.com/.well-known/openid_configuration')
        ->and(ProviderCatalog::find('microsoft')?->discoveryUrlFor([]))->toBeNull('no discovery URL before the issuer resolves');
});

it('signs a LinkedIn member in from the id_token, sending the secret in the body', function (): void {
    $key = socialSigningKey('li-1');
    $org = $this->makeOrganization();
    $this->makeVerifiedDomain($org->id, 'corp.test');

    Http::fake([
        'www.linkedin.com/oauth/.well-known/openid-configuration' => Http::response(LINKEDIN_DISCOVERY),
        'www.linkedin.com/oauth/openid/jwks' => Http::response(['keys' => [$key['jwk']]]),
        'www.linkedin.com/oauth/v2/accessToken' => Http::response([
            'access_token' => 'AQV-li-token',
            'expires_in' => 5183999,
            'scope' => 'email,openid,profile',
            'token_type' => 'Bearer',
            'id_token' => socialIdToken($key['private'], 'li-1', [
                'iss' => 'https://www.linkedin.com/oauth',
                'aud' => 'client-123',
                'sub' => '782bbtaQ',
                'name' => 'Dana Reeves',
                'given_name' => 'Dana',
                'family_name' => 'Reeves',
                'email' => 'dana@corp.test',
                'email_verified' => true,
                'locale' => 'en-US',
                'nonce' => 'nonce-li',
            ]),
        ]),
    ]);

    $connection = socialConnection('linkedin', $org->id);

    // LinkedIn publishes no auth methods, and takes only the body form — so nothing
    // about Basic was stored.
    expect(app(Connections::class)->oidcConfig($connection)->tokenEndpointAuthMethod)
        ->toBe(TokenEndpointAuthMethod::ClientSecretPost);

    $response = socialCallback($connection, 'nonce-li')->assertOk();

    $user = User::query()->findOrFail($response->json('user_id'));

    expect($user->email)->toBe('dana@corp.test')
        ->and($user->name)->toBe('Dana Reeves')
        ->and($user->email_verified_at)->not->toBeNull('LinkedIn vouched for an address in a domain this organization proved')
        ->and(IdentityLink::query()->where('user_id', $user->id)->value('subject'))->toBe('782bbtaQ');

    Http::assertSent(function (Request $request): bool {
        if (! str_contains($request->url(), '/oauth/v2/accessToken')) {
            return false;
        }

        $form = socialForm($request);

        return $form['client_id'] === 'client-123'
            && $form['client_secret'] === 'secret-456'
            && ! $request->hasHeader('Authorization');
    });

    // The identity was in the token; nothing asked UserInfo.
    Http::assertNotSent(fn (Request $request): bool => str_contains($request->url(), '/v2/userinfo'));
});

it('signs a Xero user in, linked by sub and with an address it does not claim to have verified', function (): void {
    $key = socialSigningKey('xero-1');
    $org = $this->makeOrganization();
    $this->makeVerifiedDomain($org->id, 'maple.test');

    Http::fake([
        'identity.xero.com/.well-known/openid-configuration/jwks' => Http::response(['keys' => [$key['jwk']]]),
        'identity.xero.com/.well-known/openid-configuration' => Http::response(XERO_DISCOVERY),
        'identity.xero.com/connect/token' => Http::response([
            'access_token' => 'xero-access',
            'token_type' => 'Bearer',
            'expires_in' => 1800,
            'id_token' => socialIdToken($key['private'], 'xero-1', [
                'iss' => 'https://identity.xero.com',
                'aud' => 'client-123',
                'sub' => 'a3a4dbafh3495a808ed7a7b964388f53',
                'xero_userid' => '1945393b-6eb7-4143-b083-7ab26cd7690b',
                'email' => 'pat@maple.test',
                'given_name' => 'Pat',
                'family_name' => 'Lee',
                'nonce' => 'nonce-xero',
            ]),
        ]),
    ]);

    $connection = socialConnection('xero', $org->id);
    $response = socialCallback($connection, 'nonce-xero')->assertOk();
    $user = User::query()->findOrFail($response->json('user_id'));

    expect($user->email)->toBe('pat@maple.test')
        // Xero sends no email_verified, and an absent claim is not a true one — even in
        // a domain the organization has proven.
        ->and($user->email_verified_at)->toBeNull()
        ->and(IdentityLink::query()->where('user_id', $user->id)->value('subject'))->toBe('a3a4dbafh3495a808ed7a7b964388f53');

    // Xero lists both methods, so the body form that has always been sent stays.
    Http::assertSent(fn (Request $request): bool => str_contains($request->url(), '/connect/token')
        && socialForm($request)['client_secret'] === 'secret-456'
        && ! $request->hasHeader('Authorization'));
});

it('fetches Intuit\'s documented discovery document and completes the address from UserInfo', function (): void {
    $key = socialSigningKey('intuit-1');
    $org = $this->makeOrganization();
    $this->makeVerifiedDomain($org->id, 'doe.test');

    Http::fake([
        'developer.api.intuit.com/.well-known/openid_configuration' => Http::response(INTUIT_DISCOVERY),
        'oauth.platform.intuit.com/op/v1/jwks' => Http::response(['keys' => [$key['jwk']]]),
        'oauth.platform.intuit.com/oauth2/v1/tokens/bearer' => Http::response([
            'token_type' => 'bearer',
            'expires_in' => 3600,
            'access_token' => 'intuit-access',
            'refresh_token' => 'intuit-refresh',
            // Intuit's id_token: no address, no name — the company and the times.
            'id_token' => socialIdToken($key['private'], 'intuit-1', [
                'iss' => 'https://oauth.platform.intuit.com/op/v1',
                'aud' => ['client-123'],
                'sub' => '1182d6ec-2a1f-4aa3-af3f-bb3b95db45af',
                'realmid' => '123145880168382',
                'auth_time' => time(),
                'nonce' => 'nonce-intuit',
            ]),
        ]),
        'accounts.platform.intuit.com/v1/openid_connect/userinfo' => Http::response([
            'sub' => '1182d6ec-2a1f-4aa3-af3f-bb3b95db45af',
            'email' => 'john@doe.test',
            'emailVerified' => true,
            'givenName' => 'John',
            'familyName' => 'Doe',
        ]),
    ]);

    $connection = socialConnection('intuit', $org->id);
    $response = socialCallback($connection, 'nonce-intuit')->assertOk();
    $user = User::query()->findOrFail($response->json('user_id'));

    expect($user->email)->toBe('john@doe.test')
        ->and($user->email_verified_at)->not->toBeNull('Intuit\'s camel-cased emailVerified is the flag that counts')
        ->and(IdentityLink::query()->where('user_id', $user->id)->value('subject'))->toBe('1182d6ec-2a1f-4aa3-af3f-bb3b95db45af');

    // The documented document, never the one under the issuer.
    Http::assertNotSent(fn (Request $request): bool => str_contains($request->url(), 'oauth.platform.intuit.com/op/v1/.well-known'));

    // UserInfo was asked with the access token from THIS exchange.
    Http::assertSent(fn (Request $request): bool => str_contains($request->url(), '/openid_connect/userinfo')
        && $request->header('Authorization') === ['Bearer intuit-access']);
});

it('refuses an Intuit sign-in whose UserInfo describes somebody else', function (): void {
    $key = socialSigningKey('intuit-2');
    $org = $this->makeOrganization();

    Http::fake([
        'developer.api.intuit.com/.well-known/openid_configuration' => Http::response(INTUIT_DISCOVERY),
        'oauth.platform.intuit.com/op/v1/jwks' => Http::response(['keys' => [$key['jwk']]]),
        'oauth.platform.intuit.com/oauth2/v1/tokens/bearer' => Http::response([
            'access_token' => 'intuit-access',
            'id_token' => socialIdToken($key['private'], 'intuit-2', [
                'iss' => 'https://oauth.platform.intuit.com/op/v1',
                'aud' => ['client-123'],
                'sub' => 'the-person-who-signed-in',
                'nonce' => 'nonce-x',
            ]),
        ]),
        // OIDC Core §5.3.2: the UserInfo sub MUST match the token's exactly.
        'accounts.platform.intuit.com/v1/openid_connect/userinfo' => Http::response([
            'sub' => 'somebody-else',
            'email' => 'victim@doe.test',
            'emailVerified' => true,
        ]),
    ]);

    $connection = socialConnection('intuit', $org->id);

    socialCallback($connection, 'nonce-x')->assertStatus(401);

    expect(User::query()->where('email', 'victim@doe.test')->exists())->toBeFalse();
});

it('keeps an Intuit address unverified outside a domain the organization proved', function (): void {
    $key = socialSigningKey('intuit-3');
    $org = $this->makeOrganization();

    Http::fake([
        'developer.api.intuit.com/.well-known/openid_configuration' => Http::response(INTUIT_DISCOVERY),
        'oauth.platform.intuit.com/op/v1/jwks' => Http::response(['keys' => [$key['jwk']]]),
        'oauth.platform.intuit.com/oauth2/v1/tokens/bearer' => Http::response([
            'access_token' => 'intuit-access',
            'id_token' => socialIdToken($key['private'], 'intuit-3', [
                'iss' => 'https://oauth.platform.intuit.com/op/v1',
                'aud' => ['client-123'],
                'sub' => 'intuit-sub-3',
                'nonce' => 'nonce-3',
            ]),
        ]),
        'accounts.platform.intuit.com/v1/openid_connect/userinfo' => Http::response([
            'sub' => 'intuit-sub-3',
            'email' => 'sam@elsewhere.test',
            'emailVerified' => true,
        ]),
    ]);

    $response = socialCallback(socialConnection('intuit', $org->id), 'nonce-3')->assertOk();
    $user = User::query()->findOrFail($response->json('user_id'));

    // The same rule the id_token path applies: the provider's word is carried only for
    // a domain this organization speaks for.
    expect($user->email)->toBe('sam@elsewhere.test')
        ->and($user->email_verified_at)->toBeNull();
});

it('switches to HTTP Basic only when discovery rules the body form out', function (): void {
    $key = socialSigningKey('basic-1');
    $org = $this->makeOrganization();

    Http::fake([
        'idp.basic.test/.well-known/openid-configuration' => Http::response([
            'issuer' => 'https://idp.basic.test',
            'authorization_endpoint' => 'https://idp.basic.test/authorize',
            'token_endpoint' => 'https://idp.basic.test/token',
            'jwks_uri' => 'https://idp.basic.test/jwks',
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'private_key_jwt'],
        ]),
        'idp.basic.test/token' => Http::response([
            'access_token' => 'at',
            'id_token' => socialIdToken($key['private'], 'basic-1', ['iss' => 'https://idp.basic.test', 'aud' => 'rp:1', 'sub' => 'u1', 'nonce' => 'n']),
        ]),
    ]);

    $discovered = app(OidcDiscovery::class)->fromIssuer('https://idp.basic.test');

    expect($discovered->tokenEndpointAuthMethods)->toBe(['client_secret_basic', 'private_key_jwt'])
        ->and($discovered->tokenEndpointAuthMethod())->toBe(TokenEndpointAuthMethod::ClientSecretBasic)
        ->and($discovered->toConfig()['token_endpoint_auth_method'] ?? null)->toBe('client_secret_basic');

    $connection = $this->makeConnection($org->id, ConnectionType::Oidc, 'Basic IdP', [
        ...$discovered->toConfig(),
        // A colon in the id and a space in the secret: RFC 6749 §2.3.1 form-encodes each
        // half before joining them, or the server splits the pair in the wrong place.
        'client_id' => 'rp:1',
        'client_secret' => 's3cret value',
    ]);

    $tokens = app(OidcRelyingParty::class);
    expect($tokens)->toBeInstanceOf(OidcTokenExchange::class);

    $set = $tokens->exchange($connection, 'code-1', 'https://id.test/cb');

    expect($set->accessToken)->toBe('at');

    Http::assertSent(function (Request $request): bool {
        if (! str_ends_with($request->url(), '/token')) {
            return false;
        }

        $form = socialForm($request);

        return $request->header('Authorization') === ['Basic '.base64_encode('rp%3A1:s3cret+value')]
            && ! array_key_exists('client_secret', $form)
            && ! array_key_exists('client_id', $form)
            && $form['code'] === 'code-1';
    });
});

it('chooses the token endpoint method from what discovery advertises', function (array $advertised, TokenEndpointAuthMethod $expected): void {
    expect(TokenEndpointAuthMethod::forAdvertised($advertised))->toBe($expected);
})->with([
    'silent (LinkedIn)' => [[], TokenEndpointAuthMethod::ClientSecretPost],
    'both (Xero, Intuit)' => [['client_secret_basic', 'client_secret_post'], TokenEndpointAuthMethod::ClientSecretPost],
    'basic only' => [['client_secret_basic'], TokenEndpointAuthMethod::ClientSecretBasic],
    'nothing we can do' => [['private_key_jwt'], TokenEndpointAuthMethod::ClientSecretPost],
]);

/**
 * @param  list<array<string, mixed>>  $addresses
 */
function fakeBitbucket(array $addresses): void
{
    Http::fake([
        'bitbucket.org/site/oauth2/access_token' => Http::response([
            'access_token' => 'bb-access',
            'scopes' => 'account email',
            'expires_in' => 7200,
            'refresh_token' => 'bb-refresh',
            'token_type' => 'bearer',
        ]),
        'api.bitbucket.org/2.0/user/emails' => Http::response([
            'pagelen' => 10,
            'page' => 1,
            'size' => count($addresses),
            'values' => $addresses,
        ]),
        'api.bitbucket.org/2.0/user' => Http::response([
            'type' => 'user',
            'uuid' => '{d301aafa-d676-4ee0-88be-962be7417567}',
            'account_id' => '557058:c0b72ad0-1cb5-4018-9cdc-0cde8492c443',
            'nickname' => 'dana',
            'display_name' => 'Dana Reeves',
            'account_status' => 'active',
        ]),
    ]);
}

function bitbucketPrincipal(): FederatedPrincipal
{
    $template = ProviderCatalog::find('bitbucket');
    expect($template)->toBeInstanceOf(ProviderTemplate::class);

    return app(OAuth2Client::class)->principal(
        $template,
        new OAuth2ConnectionConfig('bitbucket', 'bb-key', 'bb-secret'),
        'the-code',
        'https://id.test/callback',
    );
}

it('signs a Bitbucket user in by uuid with the confirmed primary address from the paginated list', function (): void {
    fakeBitbucket([
        ['type' => 'email', 'email' => 'old@personal.test', 'is_primary' => false, 'is_confirmed' => true],
        ['type' => 'email', 'email' => 'dana@corp.test', 'is_primary' => true, 'is_confirmed' => true],
    ]);

    $principal = bitbucketPrincipal();

    expect($principal->subject)->toBe('{d301aafa-d676-4ee0-88be-962be7417567}')
        ->and($principal->provider)->toBe('oauth2:bitbucket')
        ->and($principal->name)->toBe('Dana Reeves')
        ->and($principal->email)->toBe('dana@corp.test')
        ->and($principal->emailVerified)->toBeTrue('Bitbucket confirmed it, and said so on the entry');

    // Basic at the token endpoint, as Atlassian documents — and only Basic: a secret in
    // the body as well is two methods in one request (RFC 6749 §2.3).
    Http::assertSent(function (Request $request): bool {
        if (! str_contains($request->url(), 'oauth2/access_token')) {
            return false;
        }

        $form = socialForm($request);

        return $request->header('Authorization') === ['Basic '.base64_encode('bb-key:bb-secret')]
            && ! array_key_exists('client_secret', $form)
            && $form['grant_type'] === 'authorization_code';
    });
});

it('takes no Bitbucket address when the primary one is unconfirmed', function (): void {
    // Bitbucket lists unconfirmed addresses and lets one be primary. Taking it — even
    // unverified — would let somebody occupy an address they never received mail at.
    fakeBitbucket([
        ['type' => 'email', 'email' => 'squatted@victim.test', 'is_primary' => true, 'is_confirmed' => false],
        ['type' => 'email', 'email' => 'real@personal.test', 'is_primary' => false, 'is_confirmed' => true],
    ]);

    $principal = bitbucketPrincipal();

    expect($principal->email)->toBeNull()
        ->and($principal->emailVerified)->toBeNull()
        ->and($principal->subject)->toBe('{d301aafa-d676-4ee0-88be-962be7417567}');
});

it('sends the browser to Bitbucket with the consumer key and the catalogue scopes', function (): void {
    $template = ProviderCatalog::find('bitbucket');
    expect($template)->toBeInstanceOf(ProviderTemplate::class);

    $url = app(OAuth2Client::class)->authorizeUrl(
        $template,
        new OAuth2ConnectionConfig('bitbucket', 'bb-key', 'bb-secret'),
        'https://id.test/callback',
        'state-9',
    );

    expect($url)->toStartWith('https://bitbucket.org/site/oauth2/authorize?')
        ->toContain('client_id=bb-key')
        ->toContain('state=state-9')
        ->toContain('scope=account+email');
});

it('leaves GitHub on the body form and its unflagged primary address', function (): void {
    // The new knobs default to the old behaviour; GitHub must not have changed.
    $github = ProviderCatalog::find('github');

    expect($github?->tokenEndpointAuthMethod)->toBe(TokenEndpointAuthMethod::ClientSecretPost)
        ->and($github?->profile->emailListPath)->toBeNull()
        ->and($github?->profile->emailEntryPrimary)->toBe('primary')
        ->and($github?->profile->emailEntryVerified)->toBeNull();
});
