<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Contracts;

use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;
use Cbox\Id\Pipes\Exceptions\InvalidPipeConfiguration;
use Cbox\Id\Pipes\Exceptions\PipeNotFound;
use Cbox\Id\Pipes\Models\Pipe;
use Cbox\Id\Pipes\Models\PipeGrant;

/**
 * The pipes an environment offers: which third-party providers its people can connect,
 * through which OAuth app at that provider, asking for which scopes — and which of the
 * environment's own apps may lease the resulting tokens.
 *
 * Everything is environment-owned and every method requires an ambient environment. The
 * client secret goes in sealed and never comes back out through this contract.
 *
 * Every write takes the `$actor` it is recorded against on the audit trail — a console
 * passes the person, an API the key. Left out, the system.
 */
interface Pipes
{
    /**
     * Configure a provider for this environment. One pipe per provider.
     *
     * @param  list<string>|null  $scopes  null for the catalogue's defaults
     * @param  array<string, string>  $parameters  per-installation values (Microsoft's tenant, Salesforce's domain)
     *
     * @throws InvalidPipeConfiguration for an unknown provider, a blank credential, a bad parameter, or a provider already configured
     */
    public function configure(string $provider, string $clientId, string $clientSecret, ?array $scopes = null, array $parameters = [], ?AuditActor $actor = null): Pipe;

    /**
     * Change a pipe. Only what is passed changes; a null leaves the field alone. A new
     * secret is re-sealed. People already connected keep the scopes they consented to
     * until they connect again.
     *
     * @param  list<string>|null  $scopes
     * @param  array<string, string>|null  $parameters
     *
     * @throws PipeNotFound
     * @throws InvalidPipeConfiguration
     */
    public function update(string $pipeId, ?string $clientId = null, ?string $clientSecret = null, ?array $scopes = null, ?array $parameters = null, ?bool $enabled = null, ?AuditActor $actor = null): Pipe;

    /**
     * Remove a pipe, every grant on it and every connection through it. The connections'
     * tokens are revoked in the vault; they are NOT revoked at the provider (that is one
     * outbound call per person, which a single request cannot promise to finish) —
     * disconnect connections first when that matters.
     *
     * @throws PipeNotFound
     */
    public function remove(string $pipeId, ?AuditActor $actor = null): void;

    public function find(string $pipeId): ?Pipe;

    public function forProvider(string $provider): ?Pipe;

    /** @return list<Pipe> */
    public function all(): array;

    /**
     * Allow an app to lease the tokens people connect through this pipe. Idempotent.
     *
     * @throws PipeNotFound
     */
    public function grant(string $pipeId, string $clientId, ?AuditActor $actor = null): PipeGrant;

    /** Take an app's access away. A no-op when it had none. */
    public function revokeGrant(string $pipeId, string $clientId, ?AuditActor $actor = null): void;

    /** @return list<string> the client ids granted this pipe */
    public function grantedClients(string $pipeId): array;

    public function isGranted(string $pipeId, string $clientId): bool;
}
