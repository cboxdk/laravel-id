<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\WebAuthnVerifier;
use Cbox\Id\Identity\Models\WebAuthnCredential;
use Cbox\Id\Identity\ValueObjects\AssertionResult;
use Cbox\Id\Identity\ValueObjects\VerifiedRegistration;
use RuntimeException;

/**
 * Default binding: refuses until you bind a real verifier. WebAuthn's crypto
 * MUST wrap a vetted library (e.g. web-auth/webauthn-lib), so the platform does
 * not ship a hand-rolled default.
 */
class UnavailableWebAuthnVerifier implements WebAuthnVerifier
{
    public function verifyRegistration(string $challenge, string $clientResponseJson): VerifiedRegistration
    {
        throw $this->notConfigured();
    }

    public function verifyAssertion(WebAuthnCredential $credential, string $challenge, string $clientResponseJson): AssertionResult
    {
        throw $this->notConfigured();
    }

    private function notConfigured(): RuntimeException
    {
        return new RuntimeException(
            'No WebAuthnVerifier is configured. Bind one that wraps a vetted WebAuthn library '
            .'(e.g. web-auth/webauthn-lib) to Cbox\Id\Identity\Contracts\WebAuthnVerifier.'
        );
    }
}
