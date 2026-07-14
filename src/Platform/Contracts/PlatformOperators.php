<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Contracts;

use Cbox\Id\Platform\Exceptions\CannotSuspendLastOperator;
use Cbox\Id\Platform\Models\PlatformOperator;

/**
 * Repository for platform operators — the identities above every environment.
 *
 * Operators are never environment-scoped, so these lookups resolve identically
 * no matter which environment is pinned for the current request. That is the
 * whole point: an operator authenticates once and can then assume any plane.
 */
interface PlatformOperators
{
    public function find(string $id): ?PlatformOperator;

    public function findByEmail(string $email): ?PlatformOperator;

    /**
     * Provision a new operator. The password is hashed with the configured
     * driver on the way in.
     */
    public function create(string $email, string $password, ?string $name = null): PlatformOperator;

    /**
     * Verify a password for an operator, gated on active status — a suspended
     * operator never authenticates, even with the right credential.
     */
    public function verifyPassword(string $id, string $password): bool;

    /**
     * Whether any operator has been provisioned yet. Hosts use this to gate
     * first-run bootstrap (the initial operator is created out of band).
     */
    public function exists(): bool;

    /** Record a successful sign-in timestamp. */
    public function touchLogin(string $id): void;

    /**
     * Suspend an operator so they can no longer authenticate. Refuses to suspend
     * the last active operator (that would lock everyone out of the control
     * plane). `$actorId` attributes the action to the operator who performed it.
     *
     * @throws CannotSuspendLastOperator
     */
    public function suspend(string $id, string $actorId): void;

    /** Re-activate a suspended operator. */
    public function reactivate(string $id, string $actorId): void;
}
