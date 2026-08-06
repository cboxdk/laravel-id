<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Testing;

use Cbox\Id\Identity\Contracts\WebAuthnVerifier;
use Cbox\Id\Identity\Models\WebAuthnCredential;
use Cbox\Id\Identity\ValueObjects\AssertionResult;
use Cbox\Id\Identity\ValueObjects\VerifiedRegistration;

/**
 * A controllable WebAuthnVerifier for testing passkey orchestration without a
 * real authenticator. Set the counters to exercise the clone-detection guard.
 */
class FakeWebAuthnVerifier implements WebAuthnVerifier
{
    public function __construct(
        public string $credentialId = 'cred_1',
        public string $publicKey = 'pk',
        public int $registrationSignCount = 0,
        public int $assertionSignCount = 1,
    ) {}

    public function verifyRegistration(string $challenge, string $clientResponseJson): VerifiedRegistration
    {
        return new VerifiedRegistration($this->credentialId, $this->publicKey, $this->registrationSignCount, ['internal']);
    }

    public function verifyAssertion(WebAuthnCredential $credential, string $challenge, string $clientResponseJson): AssertionResult
    {
        return new AssertionResult($this->assertionSignCount);
    }
}
