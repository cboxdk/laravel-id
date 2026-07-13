<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Platform\Contracts\PlatformOperators;
use Cbox\Id\Platform\Models\PlatformOperator;
use Illuminate\Contracts\Hashing\Hasher;

/**
 * Eloquent-backed platform operators. No environment scope is ever applied —
 * operators live above every environment by construction (the model is not
 * environment-owned), so these queries are global.
 */
final class DatabasePlatformOperators implements PlatformOperators
{
    public function __construct(private readonly Hasher $hasher) {}

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
}
