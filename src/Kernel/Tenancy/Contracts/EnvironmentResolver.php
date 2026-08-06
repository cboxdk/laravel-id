<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Contracts;

/**
 * Resolves the {@see Environment} for an inbound request from its host — the
 * runtime entry point that engages the hard environment scope. Bound to a
 * database-backed default; a host app can swap it (e.g. header- or key-based).
 */
interface EnvironmentResolver
{
    /**
     * The environment served at the given host (custom domain or subdomain), or
     * null when the host maps to no environment.
     */
    public function resolveForHost(string $host): ?Environment;

    /**
     * The environment for a given key (its id), unscoped, or null if unknown. Lets a
     * kernel that only holds an environment KEY (e.g. the event outbox replaying a
     * stored `environment_id`) rehydrate the context without reaching for a domain model.
     */
    public function forKey(string $environmentKey): ?Environment;

    /**
     * The single-tenant / host-less fallback plane, or null when none is marked.
     * Read from durable storage (not an env var) so a horizontally-scaled,
     * stateless deployment resolves the same default across every replica.
     */
    public function defaultEnvironment(): ?Environment;
}
