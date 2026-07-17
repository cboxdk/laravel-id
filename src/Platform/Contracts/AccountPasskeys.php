<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Contracts;

use Cbox\Id\Identity\Contracts\Passkeys;
use Cbox\Id\Platform\Models\AccountWebAuthnCredential;
use Illuminate\Support\Collection;

/**
 * Passkey lifecycle for account members — the buyer plane's counterpart of the
 * subject {@see Passkeys}. Shares the vetted
 * WebAuthnVerifier for the cryptographic ceremony; only the credential store and
 * the audit actor differ.
 */
interface AccountPasskeys
{
    public function register(string $memberId, string $challenge, string $clientResponseJson, ?string $name = null): AccountWebAuthnCredential;

    /**
     * Verify an assertion and return the authenticated member's id. Rejects a
     * non-increasing signature counter as a possibly cloned authenticator.
     */
    public function authenticate(string $credentialId, string $challenge, string $clientResponseJson): string;

    public function credentialById(string $credentialId): ?AccountWebAuthnCredential;

    /**
     * @return Collection<int, AccountWebAuthnCredential>
     */
    public function forMember(string $memberId): Collection;

    /** Remove one of the member's passkeys. Returns whether it belonged to them. */
    public function remove(string $id, string $memberId): bool;
}
