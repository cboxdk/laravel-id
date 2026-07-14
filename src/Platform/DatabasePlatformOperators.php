<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Platform\Contracts\PlatformOperators;
use Cbox\Id\Platform\Exceptions\CannotSuspendLastOperator;
use Cbox\Id\Platform\Models\PlatformOperator;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\Facades\DB;

/**
 * Eloquent-backed platform operators. No environment scope is ever applied —
 * operators live above every environment by construction (the model is not
 * environment-owned), so these queries are global.
 */
final class DatabasePlatformOperators implements PlatformOperators
{
    public function __construct(
        private readonly Hasher $hasher,
        private readonly AuditLog $audit,
    ) {}

    public function find(string $id): ?PlatformOperator
    {
        return PlatformOperator::query()->whereKey($id)->first();
    }

    public function findByEmail(string $email): ?PlatformOperator
    {
        return PlatformOperator::query()->where('email', $email)->first();
    }

    public function create(string $email, string $password, ?string $name = null): PlatformOperator
    {
        return PlatformOperator::query()->create([
            'email' => $email,
            'name' => $name,
            // The model's `hashed` cast hashes with the configured driver.
            'password' => $password,
            'status' => 'active',
        ]);
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

        return $this->hasher->check($password, $operator->password);
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

            $operator->forceFill(['status' => 'suspended'])->save();
            $this->recordStatus('operator.suspended', $operator->id, $actorId);
        });
    }

    public function reactivate(string $id, string $actorId): void
    {
        $operator = PlatformOperator::query()->whereKey($id)->firstOrFail();

        if ($operator->isActive()) {
            return; // already active — idempotent
        }

        $operator->forceFill(['status' => 'active'])->save();
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
