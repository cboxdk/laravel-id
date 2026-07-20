<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Identity\Contracts\WebAuthnVerifier;
use Cbox\Id\Identity\Exceptions\ClonedAuthenticator;
use Cbox\Id\Identity\Exceptions\UnknownCredential;
use Cbox\Id\Identity\Models\WebAuthnCredential;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Platform\Contracts\AccountPasskeys;
use Cbox\Id\Platform\Models\AccountWebAuthnCredential;
use Illuminate\Support\Collection;

/**
 * Account-member passkeys. Delegates all cryptography to the shared, vetted
 * {@see WebAuthnVerifier} — registration returns a plane-agnostic value object, and
 * for assertion we hydrate a transient (unsaved) subject {@see WebAuthnCredential}
 * from the account credential's public key/id/counter purely to feed the verifier,
 * then persist the advanced counter back to the account store. This reuses the
 * exact same signature/clone/replay checks as the subject plane without forking
 * security code or coupling the verifier to two models.
 */
class DatabaseAccountPasskeys implements AccountPasskeys
{
    public function __construct(
        private readonly WebAuthnVerifier $verifier,
        private readonly AuditLog $audit,
    ) {}

    public function register(string $memberId, string $challenge, string $clientResponseJson, ?string $name = null): AccountWebAuthnCredential
    {
        $verified = $this->verifier->verifyRegistration($challenge, $clientResponseJson);

        $credential = AccountWebAuthnCredential::query()->updateOrCreate(
            ['credential_id' => $verified->credentialId],
            [
                'account_member_id' => $memberId,
                'public_key' => $verified->publicKey,
                'sign_count' => $verified->signCount,
                'transports' => $verified->transports,
                'name' => $name,
            ],
        );

        $this->record('account.passkey_registered', $memberId);

        return $credential;
    }

    public function authenticate(string $credentialId, string $challenge, string $clientResponseJson): string
    {
        $credential = $this->credentialById($credentialId);

        if ($credential === null) {
            throw UnknownCredential::make($credentialId);
        }

        // A transient subject-model view of the account credential, used only to
        // carry the public key/id/counter into the shared verifier — never saved.
        $shim = new WebAuthnCredential;
        $shim->forceFill([
            'credential_id' => $credential->credential_id,
            'public_key' => $credential->public_key,
            'sign_count' => $credential->sign_count,
        ]);

        $result = $this->verifier->verifyAssertion($shim, $challenge, $clientResponseJson);

        // Clone/replay guard: the counter must strictly advance (0 means the
        // authenticator implements no counter, which is allowed).
        if ($result->newSignCount !== 0 && $result->newSignCount <= $credential->sign_count) {
            throw ClonedAuthenticator::make($credentialId);
        }

        $credential->update(['sign_count' => $result->newSignCount]);
        $this->record('account.passkey_authenticated', $credential->account_member_id);

        return $credential->account_member_id;
    }

    public function credentialById(string $credentialId): ?AccountWebAuthnCredential
    {
        return AccountWebAuthnCredential::query()->where('credential_id', $credentialId)->first();
    }

    public function forMember(string $memberId): Collection
    {
        return AccountWebAuthnCredential::query()
            ->where('account_member_id', $memberId)
            ->orderByDesc('id')
            ->get();
    }

    public function remove(string $id, string $memberId): bool
    {
        return AccountWebAuthnCredential::query()
            ->whereKey($id)
            ->where('account_member_id', $memberId)
            ->delete() > 0;
    }

    private function record(string $action, string $memberId): void
    {
        $this->audit->record(new AuditEvent(
            action: $action,
            actorType: ActorType::AccountMember,
            actorId: $memberId,
            targetType: 'account_member',
            targetId: $memberId,
        ));
    }
}
