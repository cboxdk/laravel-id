<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\Models\WebAuthnCredential;
use Cbox\Id\Identity\ValueObjects\AssertionResult;
use Cbox\Id\Identity\ValueObjects\VerifiedRegistration;

/**
 * The security boundary for WebAuthn. Implementations wrap a vetted library
 * (e.g. web-auth/webauthn-lib) to verify the attestation/assertion, the
 * challenge, origin, RP id and signature — never hand-rolled COSE/CBOR/signature
 * parsing. Throws on anything it cannot fully trust.
 */
interface WebAuthnVerifier
{
    public function verifyRegistration(string $challenge, string $clientResponseJson): VerifiedRegistration;

    public function verifyAssertion(WebAuthnCredential $credential, string $challenge, string $clientResponseJson): AssertionResult;
}
