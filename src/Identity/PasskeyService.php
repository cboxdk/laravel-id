<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\Passkeys;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Contracts\WebAuthnVerifier;
use Cbox\Id\Identity\Exceptions\AccountInactive;
use Cbox\Id\Identity\Exceptions\ClonedAuthenticator;
use Cbox\Id\Identity\Exceptions\CredentialAlreadyRegistered;
use Cbox\Id\Identity\Exceptions\UnknownCredential;
use Cbox\Id\Identity\Models\WebAuthnCredential;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Illuminate\Support\Facades\DB;

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
        private readonly Subjects $subjects,
    ) {}

    public function register(string $userId, string $challenge, string $clientResponseJson, ?string $name = null): WebAuthnCredential
    {
        $verified = $this->verifier->verifyRegistration($challenge, $clientResponseJson);

        // A registration response's credential_id is attacker-controllable (fmt=none
        // carries no provenance proof), so we must never let an upsert reassign a
        // credential that already belongs to a different subject — doing so would let
        // one authenticated user overwrite (and lock out) another's passkey. Re-binding
        // to the SAME subject is allowed (idempotent re-register / rotate metadata).
        $existing = $this->credentialById($verified->credentialId);

        if ($existing !== null && $existing->user_id !== $userId) {
            throw CredentialAlreadyRegistered::make($verified->credentialId);
        }

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

        // AND THE ACCOUNT HAS TO STILL BE ONE. A verified assertion proves possession of
        // the authenticator and says nothing about whether its owner still works here.
        // Deprovisioning revokes sessions and grants; it does not delete WebAuthn
        // credentials, so a leaver's passkey went on producing a fresh session — the one
        // credential nobody thinks to collect on the last day, because it lives in a
        // laptop's secure enclave rather than on a piece of paper.
        //
        // AccountInactive's own docblock has said this since it was written: revoking
        // existing sessions is not enough if the login paths do not also refuse.
        // Federation login applies it; this path did not.
        //
        // Before verifyAssertion(), so a disabled account's assertion is refused without
        // this service updating the credential's signature counter on its way out.
        $this->assertActive($credential->user_id);

        $result = $this->verifier->verifyAssertion($credential, $challenge, $clientResponseJson);

        // The clone/replay guard must read and advance the counter ATOMICALLY: two
        // concurrent assertions carrying the same counter could each read the stale
        // stored value, both pass the strict-increase test, and both succeed — a
        // replay. Lock the row for the duration so the second waits, then re-reads the
        // already-advanced counter and is rejected.
        DB::transaction(function () use ($credentialId, $credential, $result): void {
            $locked = WebAuthnCredential::query()->whereKey($credential->id)->lockForUpdate()->first();

            if ($locked === null) {
                throw UnknownCredential::make($credentialId);
            }

            // Clone/replay guard: the counter must strictly advance (0 means the
            // authenticator does not implement a counter, which is allowed).
            if ($result->newSignCount !== 0 && $result->newSignCount <= $locked->sign_count) {
                throw ClonedAuthenticator::make($credentialId);
            }

            $locked->update(['sign_count' => $result->newSignCount]);
        });

        $this->audit->record(new AuditEvent(
            action: 'user.passkey_authenticated',
            actorType: ActorType::User,
            actorId: $credential->user_id,
            targetType: 'user',
            targetId: $credential->user_id,
        ));

        return $credential->user_id;
    }

    /**
     * @throws AccountInactive when the credential's owner is disabled, locked or gone
     */
    private function assertActive(string $subjectId): void
    {
        if (! $this->subjects->isActive($subjectId)) {
            throw AccountInactive::make($subjectId);
        }
    }

    public function credentialById(string $credentialId): ?WebAuthnCredential
    {
        return WebAuthnCredential::query()->where('credential_id', $credentialId)->first();
    }
}
