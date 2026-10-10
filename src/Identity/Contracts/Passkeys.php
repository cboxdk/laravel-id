<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\Exceptions\SignInMethodDisabled;
use Cbox\Id\Identity\Models\WebAuthnCredential;

interface Passkeys
{
    /**
     * Register a passkey for a subject. Refuses with {@see SignInMethodDisabled} where passkeys
     * are off ({@see SignInMethods}).
     */
    public function register(string $userId, string $challenge, string $clientResponseJson, ?string $name = null): WebAuthnCredential;

    /**
     * Verify an assertion and return the authenticated user's id. Rejects a
     * non-increasing signature counter as a possibly cloned authenticator. Refuses with
     * {@see SignInMethodDisabled} where passkeys are off, before the credential is looked up.
     */
    public function authenticate(string $credentialId, string $challenge, string $clientResponseJson): string;

    public function credentialById(string $credentialId): ?WebAuthnCredential;
}
