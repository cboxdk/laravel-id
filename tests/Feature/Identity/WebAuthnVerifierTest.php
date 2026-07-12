<?php

declare(strict_types=1);

use CBOR\ByteStringObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cbox\Id\Identity\Contracts\Passkeys;
use Cbox\Id\Identity\Contracts\WebAuthnVerifier;
use Cbox\Id\Identity\Exceptions\ClonedAuthenticator;
use Cbox\Id\Identity\Exceptions\InvalidAssertionResponse;
use Cbox\Id\Identity\Models\WebAuthnCredential;
use Cbox\Id\Identity\NativeWebAuthnVerifier;
use Cbox\Id\Identity\UnavailableWebAuthnVerifier;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

const RP_ID = 'example.test';
const ORIGIN = 'https://example.test';

/**
 * A minimal software authenticator: generates a keypair and produces genuine
 * WebAuthn registration and assertion responses signed with its private key.
 */
final class SoftwareAuthenticator
{
    public string $credentialId;

    /**
     * @param  OpenSSLAsymmetricKey  $key
     */
    public function __construct(
        private $key,
        private string $coseKey,
    ) {
        $this->credentialId = random_bytes(16);
    }

    public static function es256(): self
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $details = openssl_pkey_get_details($key);
        $x = str_pad((string) $details['ec']['x'], 32, "\0", STR_PAD_LEFT);
        $y = str_pad((string) $details['ec']['y'], 32, "\0", STR_PAD_LEFT);

        $cose = MapObject::create()
            ->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2))   // kty: EC2
            ->add(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-7))   // alg: ES256
            ->add(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1))   // crv: P-256
            ->add(NegativeIntegerObject::create(-2), ByteStringObject::create($x))
            ->add(NegativeIntegerObject::create(-3), ByteStringObject::create($y));

        return new self($key, (string) $cose);
    }

    public static function rs256(): self
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        $details = openssl_pkey_get_details($key);

        $cose = MapObject::create()
            ->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(3))    // kty: RSA
            ->add(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-257))  // alg: RS256
            ->add(NegativeIntegerObject::create(-1), ByteStringObject::create((string) $details['rsa']['n']))
            ->add(NegativeIntegerObject::create(-2), ByteStringObject::create((string) $details['rsa']['e']));

        return new self($key, (string) $cose);
    }

    public function registrationResponse(string $challenge, int $signCount = 0, string $origin = ORIGIN, string $rpId = RP_ID): string
    {
        $authData = $this->authData($rpId, 0x45, $signCount) // UP | UV | AT
            .str_repeat("\0", 16)                            // AAGUID
            .pack('n', strlen($this->credentialId))
            .$this->credentialId
            .$this->coseKey;

        $attestation = MapObject::create()
            ->add(TextStringObject::create('fmt'), TextStringObject::create('none'))
            ->add(TextStringObject::create('attStmt'), MapObject::create())
            ->add(TextStringObject::create('authData'), ByteStringObject::create($authData));

        return $this->wrap([
            'clientDataJSON' => Base64Url::encode($this->clientData('webauthn.create', $challenge, $origin)),
            'attestationObject' => Base64Url::encode((string) $attestation),
            'transports' => ['internal'],
        ], id: Base64Url::encode($this->credentialId));
    }

    public function assertionResponse(string $challenge, int $signCount = 1, string $origin = ORIGIN, string $rpId = RP_ID, bool $tamper = false): string
    {
        $authData = $this->authData($rpId, 0x05, $signCount); // UP | UV
        $clientData = $this->clientData('webauthn.get', $challenge, $origin);

        openssl_sign($authData.hash('sha256', $clientData, true), $signature, $this->key, OPENSSL_ALGO_SHA256);

        if ($tamper) {
            $signature[10] = $signature[10] === "\x00" ? "\x01" : "\x00";
        }

        return $this->wrap([
            'clientDataJSON' => Base64Url::encode($clientData),
            'authenticatorData' => Base64Url::encode($authData),
            'signature' => Base64Url::encode((string) $signature),
        ]);
    }

    private function authData(string $rpId, int $flags, int $signCount): string
    {
        return hash('sha256', $rpId, true).chr($flags).pack('N', $signCount);
    }

    private function clientData(string $type, string $challenge, string $origin): string
    {
        return (string) json_encode([
            'type' => $type,
            'challenge' => Base64Url::encode($challenge),
            'origin' => $origin,
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * @param  array<string, mixed>  $response
     */
    private function wrap(array $response, string $id = 'cred'): string
    {
        return (string) json_encode(['id' => $id, 'type' => 'public-key', 'response' => $response], JSON_THROW_ON_ERROR);
    }
}

function verifier(): NativeWebAuthnVerifier
{
    return new NativeWebAuthnVerifier(RP_ID, ORIGIN);
}

it('verifies a genuine ES256 registration and produces a usable public key', function (): void {
    $authenticator = SoftwareAuthenticator::es256();

    $registration = verifier()->verifyRegistration('reg-challenge', $authenticator->registrationResponse('reg-challenge'));

    expect($registration->credentialId)->toBe(Base64Url::encode($authenticator->credentialId))
        ->and($registration->publicKey)->toContain('BEGIN PUBLIC KEY')
        ->and($registration->transports)->toBe(['internal']);
});

it('verifies a genuine ES256 assertion signature end to end', function (): void {
    $authenticator = SoftwareAuthenticator::es256();
    $verifier = verifier();

    $registration = $verifier->verifyRegistration('reg', $authenticator->registrationResponse('reg'));
    $credential = new WebAuthnCredential([
        'public_key' => $registration->publicKey,
        'sign_count' => 0,
    ]);

    $result = $verifier->verifyAssertion($credential, 'login-challenge', $authenticator->assertionResponse('login-challenge', signCount: 7));

    expect($result->newSignCount)->toBe(7);
});

it('verifies a genuine RS256 assertion signature', function (): void {
    $authenticator = SoftwareAuthenticator::rs256();
    $verifier = verifier();

    $registration = $verifier->verifyRegistration('reg', $authenticator->registrationResponse('reg'));
    $credential = new WebAuthnCredential([
        'public_key' => $registration->publicKey,
        'sign_count' => 0,
    ]);

    $result = $verifier->verifyAssertion($credential, 'login', $authenticator->assertionResponse('login', signCount: 3));

    expect($result->newSignCount)->toBe(3);
});

it('rejects a tampered assertion signature', function (): void {
    $authenticator = SoftwareAuthenticator::es256();
    $verifier = verifier();
    $registration = $verifier->verifyRegistration('reg', $authenticator->registrationResponse('reg'));
    $credential = new WebAuthnCredential(['public_key' => $registration->publicKey, 'sign_count' => 0]);

    $verifier->verifyAssertion($credential, 'login', $authenticator->assertionResponse('login', tamper: true));
})->throws(InvalidAssertionResponse::class);

it('rejects an assertion whose challenge does not match', function (): void {
    $authenticator = SoftwareAuthenticator::es256();
    $verifier = verifier();
    $registration = $verifier->verifyRegistration('reg', $authenticator->registrationResponse('reg'));
    $credential = new WebAuthnCredential(['public_key' => $registration->publicKey, 'sign_count' => 0]);

    // Authenticator signs for a different challenge than the server expects.
    $verifier->verifyAssertion($credential, 'server-challenge', $authenticator->assertionResponse('replayed-challenge'));
})->throws(InvalidAssertionResponse::class);

it('rejects a registration from a foreign origin', function (): void {
    $authenticator = SoftwareAuthenticator::es256();

    verifier()->verifyRegistration('reg', $authenticator->registrationResponse('reg', origin: 'https://evil.test'));
})->throws(InvalidAssertionResponse::class);

it('rejects a registration for a different RP id', function (): void {
    $authenticator = SoftwareAuthenticator::es256();

    verifier()->verifyRegistration('reg', $authenticator->registrationResponse('reg', rpId: 'evil.test'));
})->throws(InvalidAssertionResponse::class);

it('drives register + authenticate through PasskeyService with the real verifier', function (): void {
    config()->set('cbox-id.webauthn.rp_id', RP_ID);
    config()->set('cbox-id.webauthn.origin', ORIGIN);

    $authenticator = SoftwareAuthenticator::es256();
    $passkeys = app(Passkeys::class);

    $credential = $passkeys->register('user_1', 'reg', $authenticator->registrationResponse('reg', signCount: 1));
    $userId = $passkeys->authenticate($credential->credential_id, 'login', $authenticator->assertionResponse('login', signCount: 9));

    expect($userId)->toBe('user_1')
        ->and($credential->fresh()?->sign_count)->toBe(9);
});

it('flags a cloned authenticator when the counter does not advance', function (): void {
    config()->set('cbox-id.webauthn.rp_id', RP_ID);
    config()->set('cbox-id.webauthn.origin', ORIGIN);

    $authenticator = SoftwareAuthenticator::es256();
    $passkeys = app(Passkeys::class);

    // Registered at counter 10; an assertion at 4 signals a clone.
    $credential = $passkeys->register('user_1', 'reg', $authenticator->registrationResponse('reg', signCount: 10));

    expect(fn () => $passkeys->authenticate($credential->credential_id, 'login', $authenticator->assertionResponse('login', signCount: 4)))
        ->toThrow(ClonedAuthenticator::class);
});

it('binds the real verifier only when configured', function (): void {
    config()->set('cbox-id.webauthn.rp_id', null);
    config()->set('cbox-id.webauthn.origin', null);
    app()->forgetInstance(WebAuthnVerifier::class);

    expect(app(WebAuthnVerifier::class))->toBeInstanceOf(UnavailableWebAuthnVerifier::class);
});
