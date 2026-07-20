<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\WebAuthn;

use CBOR\Decoder;
use CBOR\Normalizable;
use CBOR\StringStream;
use Cbox\Id\Identity\Exceptions\InvalidAssertionResponse;
use Throwable;

/**
 * Parses the binary WebAuthn `authenticatorData` structure (WebAuthn §6.1):
 * rpIdHash(32) ‖ flags(1) ‖ signCount(4) ‖ [attestedCredentialData] ‖ [extensions].
 *
 * This is fixed-layout binary parsing, not cryptography. The embedded credential
 * public key (COSE) is decoded with the vetted CBOR library.
 */
readonly class AuthenticatorData
{
    private const FLAG_USER_PRESENT = 0x01;

    private const FLAG_USER_VERIFIED = 0x04;

    private const FLAG_ATTESTED_CREDENTIAL_DATA = 0x40;

    /**
     * @param  array<int|string, mixed>|null  $credentialPublicKey
     */
    private function __construct(
        public string $rpIdHash,
        public int $flags,
        public int $signCount,
        public ?string $credentialId,
        public ?array $credentialPublicKey,
    ) {}

    public static function parse(string $bytes): self
    {
        if (strlen($bytes) < 37) {
            throw InvalidAssertionResponse::make('authenticatorData too short');
        }

        $rpIdHash = substr($bytes, 0, 32);
        $flags = ord($bytes[32]);

        /** @var array{1: int} $count */
        $count = unpack('N', substr($bytes, 33, 4));
        $signCount = $count[1];

        $credentialId = null;
        $credentialPublicKey = null;

        if (($flags & self::FLAG_ATTESTED_CREDENTIAL_DATA) !== 0) {
            [$credentialId, $credentialPublicKey] = self::parseAttestedCredentialData($bytes);
        }

        return new self($rpIdHash, $flags, $signCount, $credentialId, $credentialPublicKey);
    }

    public function userPresent(): bool
    {
        return ($this->flags & self::FLAG_USER_PRESENT) !== 0;
    }

    public function userVerified(): bool
    {
        return ($this->flags & self::FLAG_USER_VERIFIED) !== 0;
    }

    /**
     * @return array{0: string, 1: array<int|string, mixed>}
     */
    private static function parseAttestedCredentialData(string $bytes): array
    {
        if (strlen($bytes) < 55) {
            throw InvalidAssertionResponse::make('attestedCredentialData truncated');
        }

        // Skip the 16-byte AAGUID, then read the 2-byte credential id length.
        /** @var array{1: int} $lengthField */
        $lengthField = unpack('n', substr($bytes, 53, 2));
        $credentialIdLength = $lengthField[1];

        $credentialId = substr($bytes, 55, $credentialIdLength);

        if (strlen($credentialId) !== $credentialIdLength) {
            throw InvalidAssertionResponse::make('credential id length mismatch');
        }

        $coseBytes = substr($bytes, 55 + $credentialIdLength);

        try {
            $decoded = Decoder::create()->decode(new StringStream($coseBytes));
        } catch (Throwable $exception) {
            throw InvalidAssertionResponse::make('malformed COSE key: '.$exception->getMessage());
        }

        $normalized = $decoded instanceof Normalizable ? $decoded->normalize() : null;

        if (! is_array($normalized)) {
            throw InvalidAssertionResponse::make('COSE key is not a map');
        }

        return [$credentialId, $normalized];
    }
}
