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
