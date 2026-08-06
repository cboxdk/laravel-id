<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Platform\Contracts\PlatformOperators;
use Cbox\Id\Platform\Enums\OperatorStatus;
use Cbox\Id\Platform\Exceptions\CannotSuspendLastOperator;
use Cbox\Id\Platform\Models\PlatformOperator;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\Facades\DB;

/**
 * Eloquent-backed platform operators. No environment scope is ever applied —
 * operators live above every environment by construction (the model is not
 * environment-owned), so these queries are global.
 */
class DatabasePlatformOperators implements PlatformOperators
{
    public function __construct(
        private readonly Hasher $hasher,
        private readonly AuditLog $audit,
        private readonly Subjects $subjects,
        private readonly PlatformRoot $platformRoot,
    ) {}

    public function find(string $id): ?PlatformOperator
    {
        return PlatformOperator::query()->whereKey($id)->first();
    }

    public function findByEmail(string $email): ?PlatformOperator
    {
        return PlatformOperator::query()->where('email', $email)->first();
    }

    /**
     * The operator record a signed-in subject holds, if any.
     *
     * This is what turns operator authority into a PERMISSION rather than a second sign-in.
     * Once an operator is a subject, "are you staff" is a question about the session that
     * already exists — so a console can carry the platform pages in the same rail as every
     * other page and show them to whoever may see them, instead of the separate layout and
     * separate credential prompt it took when the two identities were unrelated rows.
     *
     * Suspended operators are excluded HERE rather than by the caller. Leaving it to the
     * caller is an authorization check every future call site has to remember, and
     * forgetting it fails open — a suspended operator would keep their rail.
     */
    public function findBySubject(string $subjectId): ?PlatformOperator
    {
        return PlatformOperator::query()
            ->where('subject_id', $subjectId)
            ->where('status', OperatorStatus::Active)
            ->first();
    }

    public function create(string $email, string $password, ?string $name = null): PlatformOperator
    {
        $operator = PlatformOperator::query()->create([
            'email' => $email,
            'name' => $name,
            // The model's `hashed` cast hashes with the configured driver. Retained for
            // the bootstrap window below, not as the credential of record.
            'password' => $password,
            'status' => OperatorStatus::Active,
        ]);

        $this->attachSubject($operator, $password);

        return $operator;
    }

    /**
     * Give an operator an ordinary subject, so authentication is the platform's own.
     *
     * An operator used to be a second credential store: an email and a bcrypt hash, and
     * nothing else. Everything that protects a sign-in here — the tenant's password
     * policy, breached-password refusal, lockout after repeated failures, TOTP, passkeys,
     * step-up, revoking a session — lives on the subject, and an operator had none of it.
     * The widest reach in the product sat behind the weakest door, and it was weakest
     * because it was separate.
     *
     * Written inside the PLATFORM ROOT's scope. Subjects are environment-owned, so
     * creating one under the ambient scope would file the platform's own staff inside
     * whichever tenant happened to be current — invisible where it is read, and a row in
     * a tenant that has no business holding it. Account members already do exactly this.
     *
     * With no platform root — the very first install — there is nowhere for the subject
     * to live, so the operator stays unlinked and falls back to the local hash. That
     * window closes as soon as a default environment is stamped.
     */
    private function attachSubject(PlatformOperator $operator, string $password): void
    {
        $subjectId = $this->platformRoot->run(function () use ($operator, $password): string {
            $existing = $this->subjects->findByEmail($operator->email);

            // An operator who is already an account member reuses that subject rather
            // than getting a second one for the same person and the same address. Two
            // subjects for one human is the id-space split this change exists to end.
            if ($existing !== null) {
                return $existing->id;
            }

            return $this->subjects->create($operator->email, $operator->name, $password)->id;
        });

        if ($subjectId === null) {
            return;
        }

        $operator->forceFill(['subject_id' => $subjectId])->save();
    }

    public function verifyPassword(string $id, string $password): bool
    {
        $operator = $this->find($id);

        // Status gate travels with the credential check: a suspended operator
        // never authenticates, even with the correct password.
        if ($operator === null || ! $operator->isActive()) {
            // Constant-cost dummy verify so a missing/suspended operator takes the
            // same time as a real one — no enumeration timing oracle.
            $this->hasher->check($password, $this->dummyHash());

            return false;
        }

        $subjectId = $operator->subject_id;

        if ($subjectId === null) {
            // BOOTSTRAP ONLY: no platform root existed when this operator was created, so
            // there was nowhere to put their subject. The local hash is the credential
            // until the deployment has a root, and the subject is attached on the next
            // successful sign-in — the only moment the plaintext is available to seed it.
            if (! $this->hasher->check($password, $operator->password)) {
                return false;
            }

            $this->attachSubject($operator, $password);

            return true;
        }

        return $this->platformRoot->run(
            // Both gates, and in this order: a deactivated subject — a revoked operator
            // still holding a session — never authenticates, and the dummy verify keeps
            // that refusal the same cost as a wrong password.
            function () use ($subjectId, $password): bool {
                if (! $this->subjects->isActive($subjectId)) {
                    $this->hasher->check($password, $this->dummyHash());

                    return false;
                }

                return $this->subjects->verifyPassword($subjectId, $password);
            },
        ) === true;
    }

    private ?string $dummyHash = null;

    /** A valid hash of an unguessable value, used to equalize miss-path timing. */
    private function dummyHash(): string
    {
        return $this->dummyHash ??= $this->hasher->make('cbox-id::no-such-operator');
    }

    public function exists(): bool
    {
        return PlatformOperator::query()->exists();
    }

    public function touchLogin(string $id): void
    {
        PlatformOperator::query()->whereKey($id)->update(['last_login_at' => now()]);
    }

    public function suspend(string $id, string $actorId): void
    {
        DB::transaction(function () use ($id, $actorId): void {
            $operator = PlatformOperator::query()->whereKey($id)->lockForUpdate()->firstOrFail();

            if (! $operator->isActive()) {
                return; // already suspended — idempotent
            }

            // Refuse to remove the final active operator: that would lock every
            // human out of the control plane.
            $otherActive = PlatformOperator::query()
                ->where('status', 'active')
                ->whereKeyNot($operator->getKey())
                ->exists();

            if (! $otherActive) {
                throw CannotSuspendLastOperator::make($id);
            }

            $operator->forceFill(['status' => OperatorStatus::Suspended])->save();
            $this->recordStatus('operator.suspended', $operator->id, $actorId);
        });
    }

    public function reactivate(string $id, string $actorId): void
    {
        $operator = PlatformOperator::query()->whereKey($id)->firstOrFail();

        if ($operator->isActive()) {
            return; // already active — idempotent
        }

        $operator->forceFill(['status' => OperatorStatus::Active])->save();
        $this->recordStatus('operator.reactivated', $operator->id, $actorId);
    }

    private function recordStatus(string $action, string $operatorId, string $actorId): void
    {
        $this->audit->record(new AuditEvent(
            action: $action,
            actorType: ActorType::Operator,
            actorId: $actorId,
            targetType: 'operator',
            targetId: $operatorId,
        ));
    }
}
