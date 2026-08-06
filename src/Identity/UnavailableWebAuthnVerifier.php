<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\WebAuthnVerifier;
use Cbox\Id\Identity\Models\WebAuthnCredential;
use Cbox\Id\Identity\ValueObjects\AssertionResult;
use Cbox\Id\Identity\ValueObjects\VerifiedRegistration;
use RuntimeException;

/**
 * A verifier that refuses every ceremony.
 *
 * No longer the default binding. It was, back when `rp_id`/`origin` had to be configured
 * before {@see NativeWebAuthnVerifier} could assert anything; the Relying Party is now
 * derived per environment ({@see EnvironmentRelyingParties}), so there is no unconfigured
 * state left to wait on. This is what a deployment binds to turn passkeys OFF
 * deliberately, or what a host substitutes while it wires a verifier around a different
 * vetted library.
 */
class UnavailableWebAuthnVerifier implements WebAuthnVerifier
{
    public function verifyRegistration(string $challenge, string $clientResponseJson): VerifiedRegistration
    {
        throw $this->disabled();
    }

    public function verifyAssertion(WebAuthnCredential $credential, string $challenge, string $clientResponseJson): AssertionResult
    {
        throw $this->disabled();
    }

    private function disabled(): RuntimeException
    {
        return new RuntimeException(
            'Passkeys are disabled: UnavailableWebAuthnVerifier is bound to '
            .'Cbox\Id\Identity\Contracts\WebAuthnVerifier. Drop that binding to use the built-in '
            .'verifier, or bind one wrapping another vetted WebAuthn library.'
        );
    }
}
