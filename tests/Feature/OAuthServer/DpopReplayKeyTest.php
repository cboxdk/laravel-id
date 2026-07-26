<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Cbox\Id\OAuthServer\Dpop\DpopProofValidator;
use Cbox\Id\OAuthServer\Exceptions\InvalidDpopProof;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/**
 * A fresh P-256 keypair plus its public JWK. Coordinates are left-padded to the
 * curve's field length (RFC 7518 §6.2.1.2) — OpenSSL strips leading zero bytes, and
 * an unpadded coordinate rebuilds the wrong point.
 *
 * @return array{pem: string, jwk: array<string, string>}
 */
function replayKeyPair(): array
{
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    openssl_pkey_export($key, $pem);
    $details = openssl_pkey_get_details($key);

    $b64 = static fn (string $binary): string => rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');

    return [
        'pem' => (string) $pem,
        'jwk' => [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => $b64(str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT)),
            'y' => $b64(str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT)),
        ],
    ];
}

/**
 * @param  array{pem: string, jwk: array<string, string>}  $key
 */
function replayProof(array $key, string $jti): string
{
    return JWT::encode([
        'htm' => 'POST',
        'htu' => 'https://id.test/oauth/token',
        'iat' => time(),
        'jti' => $jti,
    ], $key['pem'], 'ES256', null, ['typ' => 'dpop+jwt', 'jwk' => $key['jwk']]);
}

it('accepts the same jti from two different keys, because a jti is only unique per key', function (): void {
    $validator = app(DpopProofValidator::class);
    $shared = 'a-nonce-both-clients-happened-to-pick';

    $first = replayKeyPair();
    $second = replayKeyPair();

    $jktOne = $validator->verify(replayProof($first, $shared), 'POST', 'https://id.test/oauth/token');

    // Before the replay key became (jkt, jti) this threw: the global unique(jti)
    // rejected an unrelated client's perfectly valid proof as a replay.
    $jktTwo = $validator->verify(replayProof($second, $shared), 'POST', 'https://id.test/oauth/token');

    expect($jktOne)->not->toBe($jktTwo)
        ->and(DB::table('dpop_proofs')->where('jti', $shared)->count())->toBe(2);
});

it('still refuses the same proof twice from the same key', function (): void {
    $validator = app(DpopProofValidator::class);
    $key = replayKeyPair();
    $proof = replayProof($key, 'single-use-nonce');

    $validator->verify($proof, 'POST', 'https://id.test/oauth/token');

    expect(fn () => $validator->verify($proof, 'POST', 'https://id.test/oauth/token'))
        ->toThrow(InvalidDpopProof::class, 'proof replay detected');
});

it('records the thumbprint it keyed the proof under', function (): void {
    $key = replayKeyPair();

    $jkt = app(DpopProofValidator::class)->verify(
        replayProof($key, 'thumbprint-nonce'),
        'POST',
        'https://id.test/oauth/token',
    );

    expect(DB::table('dpop_proofs')->where('jti', 'thumbprint-nonce')->value('jkt'))->toBe($jkt);
});

it('stamps the environment the proof was seen in', function (): void {
    $key = replayKeyPair();

    app(EnvironmentContext::class)->runAs(
        GenericEnvironment::of('env-01'),
        fn () => app(DpopProofValidator::class)->verify(
            replayProof($key, 'scoped-nonce'),
            'POST',
            'https://id.test/oauth/token',
        ),
    );

    expect(DB::table('dpop_proofs')->where('jti', 'scoped-nonce')->value('environment_id'))->toBe('env-01');
});

it('still records on the platform plane, which has no environment', function (): void {
    $key = replayKeyPair();

    // The account-management plane deliberately runs outside any environment; a
    // nullable column is what lets the replay guard keep working there.
    app(EnvironmentContext::class)->set(null);

    app(DpopProofValidator::class)->verify(
        replayProof($key, 'platform-nonce'),
        'POST',
        'https://id.test/oauth/token',
    );

    expect(DB::table('dpop_proofs')->where('jti', 'platform-nonce')->value('environment_id'))->toBeNull();
});
