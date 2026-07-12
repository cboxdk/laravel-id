<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use CBOR\Decoder;
use CBOR\Normalizable;
use CBOR\StringStream;
use Cbox\Id\Identity\Contracts\WebAuthnVerifier;
use Cbox\Id\Identity\Exceptions\InvalidAssertionResponse;
use Cbox\Id\Identity\Exceptions\UnsupportedCredential;
use Cbox\Id\Identity\Models\WebAuthnCredential;
use Cbox\Id\Identity\ValueObjects\AssertionResult;
use Cbox\Id\Identity\ValueObjects\VerifiedRegistration;
use Cbox\Id\Identity\WebAuthn\AuthenticatorData;
use Cbox\Id\Identity\WebAuthn\CoseKey;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Throwable;

/**
 * A real WebAuthn verifier. Signature verification is delegated to OpenSSL and
 * COSE/CBOR decoding to the vetted spomky-labs/cbor-php library — no hand-rolled
 * cryptography. It enforces the WebAuthn verification steps that matter for
 * security: ceremony type, challenge binding, origin + RP-id binding, user
 * presence, and the assertion signature over authenticatorData ‖ hash(clientData).
 *
 * Supported credential algorithms: ES256 (P-256) and RS256. Attestation formats:
 * `none` and self-attestation `packed`; any other format is rejected rather than
 * trusted (a caller wanting full attestation-chain validation binds its own).
 */
final class NativeWebAuthnVerifier implements WebAuthnVerifier
{
    public function __construct(
        private readonly string $rpId,
        private readonly string $origin,
    ) {}

    public function verifyRegistration(string $challenge, string $clientResponseJson): VerifiedRegistration
    {
        $response = $this->response($clientResponseJson);
        $clientDataRaw = $this->verifyClientData($response, 'webauthn.create', $challenge);

        $attestation = $this->decodeCbor($this->b64url($response, 'attestationObject'), 'attestationObject');

        $authDataBytes = $attestation['authData'] ?? null;
        if (! is_string($authDataBytes)) {
            throw InvalidAssertionResponse::make('attestationObject missing authData');
        }

        $authData = AuthenticatorData::parse($authDataBytes);
        $this->assertRpAndPresence($authData);

        if ($authData->credentialId === null || $authData->credentialPublicKey === null) {
            throw InvalidAssertionResponse::make('registration is missing attested credential data');
        }

        $publicKeyPem = CoseKey::toPem($authData->credentialPublicKey);

        $this->verifyAttestation($attestation, $authDataBytes, $clientDataRaw, $publicKeyPem);

        return new VerifiedRegistration(
            credentialId: Base64Url::encode($authData->credentialId),
            publicKey: $publicKeyPem,
            signCount: $authData->signCount,
            transports: $this->transports($response),
        );
    }

    public function verifyAssertion(WebAuthnCredential $credential, string $challenge, string $clientResponseJson): AssertionResult
    {
        $response = $this->response($clientResponseJson);
        $clientDataRaw = $this->verifyClientData($response, 'webauthn.get', $challenge);

        $authDataBytes = $this->b64url($response, 'authenticatorData');
        $authData = AuthenticatorData::parse($authDataBytes);
        $this->assertRpAndPresence($authData);

        $signature = $this->b64url($response, 'signature');
        $signedData = $authDataBytes.hash('sha256', $clientDataRaw, true);

        if (openssl_verify($signedData, $signature, $credential->public_key, OPENSSL_ALGO_SHA256) !== 1) {
            throw InvalidAssertionResponse::make('assertion signature verification failed');
        }

        return new AssertionResult($authData->signCount);
    }

    /**
     * Verify the attestation statement. `none` needs none; self-attestation
     * `packed` (no x5c) is verified against the credential's own public key.
     *
     * @param  array<string, mixed>  $attestation
     */
    private function verifyAttestation(array $attestation, string $authDataBytes, string $clientDataRaw, string $publicKeyPem): void
    {
        $fmt = $attestation['fmt'] ?? null;

        if ($fmt === 'none') {
            return;
        }

        if ($fmt !== 'packed') {
            throw UnsupportedCredential::make('unsupported attestation format ['.(is_string($fmt) ? $fmt : gettype($fmt)).']');
        }

        $statement = $attestation['attStmt'] ?? null;
        if (! is_array($statement)) {
            throw InvalidAssertionResponse::make('packed attestation missing statement');
        }

        if (isset($statement['x5c'])) {
            throw UnsupportedCredential::make('full (x5c) attestation chains are not verified by this verifier');
        }

        $signature = $statement['sig'] ?? null;
        if (! is_string($signature)) {
            throw InvalidAssertionResponse::make('packed attestation missing signature');
        }

        $signedData = $authDataBytes.hash('sha256', $clientDataRaw, true);

        if (openssl_verify($signedData, $signature, $publicKeyPem, OPENSSL_ALGO_SHA256) !== 1) {
            throw InvalidAssertionResponse::make('self-attestation signature verification failed');
        }
    }

    private function assertRpAndPresence(AuthenticatorData $authData): void
    {
        if (! hash_equals(hash('sha256', $this->rpId, true), $authData->rpIdHash)) {
            throw InvalidAssertionResponse::make('RP id hash mismatch');
        }

        if (! $authData->userPresent()) {
            throw InvalidAssertionResponse::make('user-presence flag not set');
        }
    }

    /**
     * @param  array<string, mixed>  $response
     */
    private function verifyClientData(array $response, string $expectedType, string $challenge): string
    {
        $clientDataRaw = $this->b64url($response, 'clientDataJSON');

        $decoded = json_decode($clientDataRaw, true);
        if (! is_array($decoded)) {
            throw InvalidAssertionResponse::make('clientDataJSON is not valid JSON');
        }

        $type = $decoded['type'] ?? null;
        if ($type !== $expectedType) {
            throw InvalidAssertionResponse::make("unexpected ceremony type (want {$expectedType})");
        }

        $presentedChallenge = $decoded['challenge'] ?? null;
        if (! is_string($presentedChallenge) || ! hash_equals(Base64Url::encode($challenge), $presentedChallenge)) {
            throw InvalidAssertionResponse::make('challenge mismatch');
        }

        $presentedOrigin = $decoded['origin'] ?? null;
        if (! is_string($presentedOrigin) || ! hash_equals($this->origin, $presentedOrigin)) {
            throw InvalidAssertionResponse::make('origin mismatch');
        }

        return $clientDataRaw;
    }

    /**
     * @return array<string, mixed>
     */
    private function response(string $clientResponseJson): array
    {
        $decoded = json_decode($clientResponseJson, true);
        if (! is_array($decoded)) {
            throw InvalidAssertionResponse::make('client response is not valid JSON');
        }

        $response = $decoded['response'] ?? $decoded;
        if (! is_array($response)) {
            throw InvalidAssertionResponse::make('client response missing "response"');
        }

        /** @var array<string, mixed> $response */
        return $response;
    }

    /**
     * @param  array<string, mixed>  $response
     */
    private function b64url(array $response, string $key): string
    {
        $value = $response[$key] ?? null;
        if (! is_string($value) || $value === '') {
            throw InvalidAssertionResponse::make("missing [{$key}]");
        }

        try {
            return Base64Url::decode($value);
        } catch (Throwable) {
            throw InvalidAssertionResponse::make("[{$key}] is not valid base64url");
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeCbor(string $bytes, string $label): array
    {
        try {
            $decoded = Decoder::create()->decode(new StringStream($bytes));
        } catch (Throwable $exception) {
            throw InvalidAssertionResponse::make("malformed {$label}: ".$exception->getMessage());
        }

        $normalized = $decoded instanceof Normalizable ? $decoded->normalize() : null;
        if (! is_array($normalized)) {
            throw InvalidAssertionResponse::make("{$label} is not a CBOR map");
        }

        /** @var array<string, mixed> $normalized */
        return $normalized;
    }

    /**
     * @param  array<string, mixed>  $response
     * @return list<string>
     */
    private function transports(array $response): array
    {
        $transports = $response['transports'] ?? null;
        if (! is_array($transports)) {
            return [];
        }

        return array_values(array_filter($transports, 'is_string'));
    }
}
