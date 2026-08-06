<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Dpop\DpopProofValidator;
use Cbox\Id\OAuthServer\Exceptions\InvalidDpopProof;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * Every other DPoP assertion in the suite compares the produced `jkt` against a
 * thumbprint the TEST computes with the same canonicalization the implementation
 * uses — a round trip that stays green even if both sides are wrong together.
 * These cases come from the RFCs themselves: published key documents with published
 * thumbprints. A `jkt` is the name a client, the token endpoint and the resource
 * server each derive independently, so the canonical member set and its order are
 * wire contract. Include `alg`/`kid`, drop a member, or emit `kty` before `crv` and
 * every conforming peer computes a different value while our own round trip passes.
 *
 * @return array<string, array{0: array<string, mixed>}>
 */
function jwkThumbprintFixtureCases(): array
{
    $path = dirname(__DIR__, 2).'/Fixtures/OAuthServer/jwk_thumbprint.json';
    /** @var array{cases: list<array<string, mixed>>} $data */
    $data = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);

    $dataset = [];
    foreach ($data['cases'] as $case) {
        $dataset[$case['name']] = [$case];
    }

    return $dataset;
}

/**
 * The validator's thumbprint is private (it is an implementation detail of proof
 * verification, not an API), and the RFC vectors publish no private key to sign a
 * proof with — so the canonicalization is driven directly.
 *
 * @param  array<string, mixed>  $jwk
 */
function thumbprintOf(array $jwk): string
{
    $validator = app(DpopProofValidator::class);

    /** @var string */
    return (new ReflectionMethod($validator, 'thumbprint'))->invoke($validator, $jwk);
}

it('reproduces the published RFC JWK thumbprint vectors', function (array $case): void {
    // The RFC's own key document, extra members (alg, kid) and all — those must not
    // enter the hash.
    expect(thumbprintOf($case['jwk']))->toBe($case['thumbprint']);

    // And the fixture is itself an honest vector: its canonical bytes really do hash
    // to the published thumbprint, so a future edit cannot quietly weaken it.
    expect(hash('sha256', $case['canonical_json']))->toBe($case['sha256_hex'])
        ->and(Base64Url::encode(hash('sha256', $case['canonical_json'], true)))->toBe($case['thumbprint']);
})->with(jwkThumbprintFixtureCases());

it('ignores non-canonical members and member order in the input JWK', function (): void {
    $path = dirname(__DIR__, 2).'/Fixtures/OAuthServer/jwk_thumbprint.json';
    /** @var array{cases: list<array{name: string, jwk: array<string, mixed>, thumbprint: string}>} $data */
    $data = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
    $rsa = $data['cases'][0];

    // Same key, members shuffled and decorated the way a real client library might
    // serialize them. RFC 7638 §3 canonicalizes before hashing, so the thumbprint is
    // unchanged — it names the KEY, not the encoding.
    $shuffled = [
        'use' => 'sig',
        'n' => $rsa['jwk']['n'],
        'kid' => 'something-else-entirely',
        'kty' => 'RSA',
        'key_ops' => ['verify'],
        'e' => 'AQAB',
    ];

    expect(thumbprintOf($shuffled))->toBe($rsa['thumbprint']);
});

it('refuses to thumbprint a JWK missing a required member', function (): void {
    // A key type whose required set is incomplete has no defined thumbprint; it must
    // fail rather than hash a null into a stable-looking value.
    expect(fn (): string => thumbprintOf(['kty' => 'RSA', 'e' => 'AQAB']))
        ->toThrow(InvalidDpopProof::class)
        ->and(fn (): string => thumbprintOf(['kty' => 'oct', 'k' => 'AQAB']))
        ->toThrow(InvalidDpopProof::class);
});

it('binds an RS256 DPoP proof to the RFC 7638 thumbprint of its embedded RSA key', function (): void {
    // The RSA branch of the thumbprint reached the way a real client reaches it —
    // through a signed proof — rather than only through the vector above. (The RFC
    // publishes no private key, so this needs a fresh one.)
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    openssl_pkey_export($key, $pem);
    $details = openssl_pkey_get_details($key);

    $jwk = [
        'kty' => 'RSA',
        'n' => Base64Url::encode($details['rsa']['n']),
        'e' => Base64Url::encode($details['rsa']['e']),
    ];

    $proof = JWT::encode(
        ['htm' => 'POST', 'htu' => 'https://id.test/oauth/token', 'iat' => time(), 'jti' => bin2hex(random_bytes(12))],
        (string) $pem,
        'RS256',
        null,
        ['typ' => 'dpop+jwt', 'jwk' => $jwk],
    );

    $jkt = app(DpopProofValidator::class)->verify($proof, 'POST', 'https://id.test/oauth/token');

    // Exactly the RFC 7638 construction the vectors above pin: {"e":…,"kty":"RSA","n":…}.
    $expected = Base64Url::encode(hash(
        'sha256',
        (string) json_encode(['e' => $jwk['e'], 'kty' => 'RSA', 'n' => $jwk['n']]),
        true,
    ));

    expect($jkt)->toBe($expected)->toHaveLength(43);
});
