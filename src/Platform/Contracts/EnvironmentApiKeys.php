<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Contracts;

use Cbox\Id\Platform\Models\EnvironmentApiKey;
use Cbox\Id\Platform\ValueObjects\IssuedEnvironmentApiKey;
use DateTimeInterface;
use Illuminate\Support\Collection;

/**
 * Repository for environment API keys — the environment-plane machine credential.
 * Every operation is bound to a single environment: a key can only ever be issued
 * into, listed from, resolved within, or revoked from its own environment.
 */
interface EnvironmentApiKeys
{
    /**
     * Issue a new key into an environment. Returns the stored record plus the
     * one-time plaintext, which is never recoverable afterwards. `scopes` is the
     * allow-list the key carries (deny-by-default).
     *
     * @param  list<string>  $scopes
     */
    public function issue(string $environmentId, string $name, array $scopes, ?DateTimeInterface $expiresAt = null): IssuedEnvironmentApiKey;

    /**
     * Resolve a presented plaintext token to its active key WITHIN THE CURRENT
     * environment, recording use. Because the model is hard-scoped, a key belonging
     * to a different environment cannot resolve here at all. Returns null for an
     * unknown, revoked, expired, or wrong-environment token.
     */
    public function resolve(string $plaintext): ?EnvironmentApiKey;

    /** Revoke a key immediately within its environment (idempotent). */
    public function revoke(string $environmentId, string $id): void;

    /**
     * Every key issued for an environment (including revoked/expired, for the audit
     * list), newest first.
     *
     * @return Collection<int, EnvironmentApiKey>
     */
    public function forEnvironment(string $environmentId): Collection;
}
