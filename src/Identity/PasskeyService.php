<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\Passkeys;
use Cbox\Id\Identity\Contracts\WebAuthnVerifier;
use Cbox\Id\Identity\Exceptions\ClonedAuthenticator;
use Cbox\Id\Identity\Exceptions\UnknownCredential;
use Cbox\Id\Identity\Models\WebAuthnCredential;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;

/**
 * Passkey ceremony orchestration + credential lifecycle. The cryptographic
 * verification is delegated to a {@see WebAuthnVerifier}; this service owns the
 * storage and the clone-detection / replay guard on the signature counter.
 */
class PasskeyService implements Passkeys
{
    public function __construct(
        private readonly WebAuthnVerifier $verifier,
        private readonly AuditLog $audit,
    ) {}

    public function register(string $userId, string $challenge, string $clientResponseJson, ?string $name = null): WebAuthnCredential
    {
        $verified = $this->verifier->verifyRegistration($challenge, $clientResponseJson);

        $credential = WebAuthnCredential::query()->updateOrCreate(
            ['credential_id' => $verified->credentialId],
            [
                'user_id' => $userId,
                'public_key' => $verified->publicKey,
                'sign_count' => $verified->signCount,
                'transports' => $verified->transports,
                'name' => $name,
            ],
        );

        $this->audit->record(new AuditEvent(
            action: 'user.passkey_registered',
            actorType: ActorType::User,
            actorId: $userId,
            targetType: 'user',
            targetId: $userId,
        ));

        return $credential;
    }

    public function authenticate(string $credentialId, string $challenge, string $clientResponseJson): string
    {
        $credential = $this->credentialById($credentialId);

        if ($credential === null) {
            throw UnknownCredential::make($credentialId);
        }

        $result = $this->verifier->verifyAssertion($credential, $challenge, $clientResponseJson);

        // Clone/replay guard: the counter must strictly advance (0 means the
        // authenticator does not implement a counter, which is allowed).
        if ($result->newSignCount !== 0 && $result->newSignCount <= $credential->sign_count) {
            throw ClonedAuthenticator::make($credentialId);
        }

        $credential->update(['sign_count' => $result->newSignCount]);

        $this->audit->record(new AuditEvent(
            action: 'user.passkey_authenticated',
            actorType: ActorType::User,
            actorId: $credential->user_id,
            targetType: 'user',
            targetId: $credential->user_id,
        ));

        return $credential->user_id;
    }

    public function credentialById(string $credentialId): ?WebAuthnCredential
    {
        return WebAuthnCredential::query()->where('credential_id', $credentialId)->first();
    }
}
