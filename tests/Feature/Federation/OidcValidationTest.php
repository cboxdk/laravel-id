<?php

declare(strict_types=1);

use Cbox\Id\Federation\Contracts\AssertionValidator;
use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\FederationFlow;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Identity\Contracts\Subjects;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

/**
 * @return array{private: string, public: string}
 */
function rsaKeypair(): array
{
    $resource = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);

    if ($resource === false) {
        throw new RuntimeException('could not generate test keypair');
    }

    openssl_pkey_export($resource, $privatePem);
    $details = openssl_pkey_get_details($resource);

    return ['private' => (string) $privatePem, 'public' => (string) ($details['key'] ?? '')];
}

/**
 * Build a public RSA JWK (RFC 7517) from a PEM, as an IdP's jwks_uri would serve.
 *
 * @return array<string, string>
 */
function rsaJwk(string $publicPem, string $kid): array
{
    $details = openssl_pkey_get_details(openssl_pkey_get_public($publicPem));
    $b64u = fn (string $bin): string => rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');

    return [
        'kty' => 'RSA',
        'kid' => $kid,
        'use' => 'sig',
        'alg' => 'RS256',
        'n' => $b64u((string) ($details['rsa']['n'] ?? '')),
        'e' => $b64u((string) ($details['rsa']['e'] ?? '')),
    ];
}

/**
 * @param  array<string, mixed>  $overrides
 */
function idToken(string $privatePem, array $overrides = [], string $kid = 'kid-1'): string
{
    $claims = array_merge([
        'iss' => 'https://idp.test',
        'aud' => 'client-123',
        'sub' => 'idp|alice',
        'email' => 'alice@corp.com',
        'name' => 'Alice',
        'iat' => time(),
        'exp' => time() + 300,
    ], $overrides);

    return JWT::encode($claims, $privatePem, 'RS256', $kid);
}

/**
 * @param  array<string, mixed>  $configOverrides
 */
function oidcConnection(array $configOverrides = [], ?string $organizationId = null): Connection
{
    $connections = app(Connections::class);

    $connection = $connections->create(
        $organizationId ?? (string) Str::ulid(),
        ConnectionType::Oidc,
        'Entra',
        array_merge(['issuer' => 'https://idp.test', 'client_id' => 'client-123'], $configOverrides),
    );
    $connections->activate($connection->organization_id, $connection->id);

    return $connection->refresh();
}

it('validates a well-formed id_token into a principal', function (): void {
    $keys = rsaKeypair();
    $connection = oidcConnection(['signing_keys' => ['kid-1' => $keys['public']]]);

    $principal = app(AssertionValidator::class)->validate($connection, idToken($keys['private']));

    expect($principal->subject)->toBe('idp|alice')
        ->and($principal->email)->toBe('alice@corp.com')
        ->and($principal->name)->toBe('Alice')
        ->and($principal->provider)->toBe('oidc')
        ->and($principal->connectionId)->toBe($connection->id);
});

it('accepts a single signing_key when the IdP omits kid', function (): void {
    $keys = rsaKeypair();
    $connection = oidcConnection(['signing_key' => $keys['public']]);

    $token = JWT::encode([
        'iss' => 'https://idp.test',
        'aud' => 'client-123',
        'sub' => 'idp|bob',
        'exp' => time() + 300,
    ], $keys['private'], 'RS256');

    expect(app(AssertionValidator::class)->validate($connection, $token)->subject)->toBe('idp|bob');
});

it('rejects a token signed by an unknown key', function (): void {
    $trusted = rsaKeypair();
    $attacker = rsaKeypair();
    $connection = oidcConnection(['signing_keys' => ['kid-1' => $trusted['public']]]);

    app(AssertionValidator::class)->validate($connection, idToken($attacker['private']));
})->throws(InvalidAssertion::class);

it('fetches the IdP JWKS and picks up a signing-key rotation by kid', function (): void {
    config(['cbox-id.federation.verify_url' => false]);
    $old = rsaKeypair();
    $new = rsaKeypair();
    $connection = oidcConnection(['jwks_uri' => 'https://idp.test/jwks']);

    // First fetch serves the old key; the forced refetch after the kid-miss serves the
    // rotated key — exactly two fetches (cache miss, then forced refresh).
    Http::fakeSequence('idp.test/*')
        ->push(['keys' => [rsaJwk($old['public'], 'kid-1')]])
        ->push(['keys' => [rsaJwk($new['public'], 'kid-2')]]);

    expect(app(AssertionValidator::class)->validate($connection, idToken($old['private'], [], 'kid-1'))->subject)
        ->toBe('idp|alice');

    // The IdP rotated its signing key: a new kid the cached JWKS doesn't know. The
    // kid-miss must trigger a fresh fetch and validate the new token with no admin action.
    expect(app(AssertionValidator::class)->validate($connection, idToken($new['private'], [], 'kid-2'))->subject)
        ->toBe('idp|alice');
});

it('pins RS256 on a fetched JWKS — rejects an HS256 token forged with the RSA public key', function (): void {
    config(['cbox-id.federation.verify_url' => false]);
    $keys = rsaKeypair();
    $connection = oidcConnection(['jwks_uri' => 'https://idp.test/jwks']);
    Http::fake(['https://idp.test/jwks' => Http::response(['keys' => [rsaJwk($keys['public'], 'kid-1')]])]);

    // Classic algorithm-confusion: HMAC-sign with the RSA PUBLIC key as the secret.
    $forged = JWT::encode([
        'iss' => 'https://idp.test', 'aud' => 'client-123', 'sub' => 'attacker', 'exp' => time() + 300,
    ], $keys['public'], 'HS256', 'kid-1');

    app(AssertionValidator::class)->validate($connection, $forged);
})->throws(InvalidAssertion::class);

it('rejects an alg:none token even with a JWKS configured', function (): void {
    config(['cbox-id.federation.verify_url' => false]);
    $keys = rsaKeypair();
    $connection = oidcConnection(['jwks_uri' => 'https://idp.test/jwks']);
    Http::fake(['https://idp.test/jwks' => Http::response(['keys' => [rsaJwk($keys['public'], 'kid-1')]])]);

    $b64u = fn (string $s): string => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    $none = $b64u((string) json_encode(['alg' => 'none', 'typ' => 'JWT', 'kid' => 'kid-1']))
        .'.'.$b64u((string) json_encode(['iss' => 'https://idp.test', 'aud' => 'client-123', 'sub' => 'x', 'exp' => time() + 300]))
        .'.';

    app(AssertionValidator::class)->validate($connection, $none);
})->throws(InvalidAssertion::class);

it('rejects a token whose issuer does not match', function (): void {
    $keys = rsaKeypair();
    $connection = oidcConnection(['signing_keys' => ['kid-1' => $keys['public']]]);

    app(AssertionValidator::class)->validate($connection, idToken($keys['private'], ['iss' => 'https://evil.test']));
})->throws(InvalidAssertion::class);

it('rejects a token whose audience does not match', function (): void {
    $keys = rsaKeypair();
    $connection = oidcConnection(['signing_keys' => ['kid-1' => $keys['public']]]);

    app(AssertionValidator::class)->validate($connection, idToken($keys['private'], ['aud' => 'someone-else']));
})->throws(InvalidAssertion::class);

it('rejects a multi-audience id_token that omits azp (OIDC Core §3.1.3.7)', function (): void {
    $keys = rsaKeypair();
    $connection = oidcConnection(['signing_keys' => ['kid-1' => $keys['public']]]);

    // Our client_id is present, but the token names a second audience and carries no
    // azp — the spec requires azp for a multi-audience id_token.
    app(AssertionValidator::class)->validate($connection, idToken($keys['private'], [
        'aud' => ['client-123', 'attacker-client'],
    ]));
})->throws(InvalidAssertion::class);

it('rejects a multi-audience id_token whose azp names a different party (token laundering)', function (): void {
    $keys = rsaKeypair();
    $connection = oidcConnection(['signing_keys' => ['kid-1' => $keys['public']]]);

    // The upstream IdP minted this for the attacker (azp) and merely *listed* us in aud.
    // Membership in aud must not be enough — azp must equal our client_id.
    app(AssertionValidator::class)->validate($connection, idToken($keys['private'], [
        'aud' => ['client-123', 'attacker-client'],
        'azp' => 'attacker-client',
    ]));
})->throws(InvalidAssertion::class);

it('accepts a multi-audience id_token when azp names us', function (): void {
    $keys = rsaKeypair();
    $connection = oidcConnection(['signing_keys' => ['kid-1' => $keys['public']]]);

    $principal = app(AssertionValidator::class)->validate($connection, idToken($keys['private'], [
        'aud' => ['client-123', 'other-resource'],
        'azp' => 'client-123',
    ]));

    expect($principal->subject)->toBe('idp|alice');
});

it('rejects a single-audience id_token whose azp names a different party', function (): void {
    $keys = rsaKeypair();
    $connection = oidcConnection(['signing_keys' => ['kid-1' => $keys['public']]]);

    // azp present but not us: OIDC Core §3.1.3.7 (5) — reject whenever azp != client_id.
    app(AssertionValidator::class)->validate($connection, idToken($keys['private'], [
        'azp' => 'attacker-client',
    ]));
})->throws(InvalidAssertion::class);

it('rejects an expired token', function (): void {
    $keys = rsaKeypair();
    $connection = oidcConnection(['signing_keys' => ['kid-1' => $keys['public']]]);

    app(AssertionValidator::class)->validate($connection, idToken($keys['private'], [
        'iat' => time() - 600,
        'exp' => time() - 300,
    ]));
})->throws(InvalidAssertion::class);

it('rejects a token missing a subject', function (): void {
    $keys = rsaKeypair();
    $connection = oidcConnection(['signing_keys' => ['kid-1' => $keys['public']]]);

    $token = JWT::encode([
        'iss' => 'https://idp.test',
        'aud' => 'client-123',
        'exp' => time() + 300,
    ], $keys['private'], 'RS256', 'kid-1');

    app(AssertionValidator::class)->validate($connection, $token);
})->throws(InvalidAssertion::class);

it('refuses a connection type with no registered validator (SAML)', function (): void {
    $org = $this->makeOrganization();
    $connection = $this->makeConnection($org->id, ConnectionType::Saml, config: ['issuer' => 'x']);

    app(AssertionValidator::class)->validate($connection, 'anything');
})->throws(InvalidAssertion::class);

it('drives an end-to-end OIDC SSO login through the federation flow', function (): void {
    $keys = rsaKeypair();
    $org = $this->makeOrganization();
    $connection = oidcConnection(['signing_keys' => ['kid-1' => $keys['public']]], $org->id);

    $principal = app(AssertionValidator::class)->validate($connection, idToken($keys['private']));
    $session = app(FederationFlow::class)->completeLogin($connection, $principal);

    $user = app(Subjects::class)->findByEmail('alice@corp.com');

    expect($user)->not->toBeNull()
        ->and($session->user_id)->toBe($user?->id)
        ->and($session->amr)->toBe(['sso']);
});
