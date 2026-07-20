<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Testing;

use Cbox\Id\Provisioning\Contracts\ScimClient;
use Cbox\Id\Provisioning\Models\ProvisioningConnection;
use Cbox\Id\Provisioning\ValueObjects\ScimResult;
use Illuminate\Support\Str;

/**
 * An in-memory downstream SCIM 2.0 server, standing in for a real one so the
 * suite can drive the whole lifecycle against REAL payload shapes (it records the
 * exact resource / PatchOp bodies the service builds) without HTTP.
 *
 * It behaves like a conformant server: POST assigns and returns a remote `id`;
 * PATCH/DELETE against an unknown id return 404; a pre-seeded `externalId`
 * produces a 409 on create and is discoverable by filter. Faults can be injected
 * (`failWith`, `failTransport`) and remote records dropped (`dropRemote`) to
 * exercise reconcile and retry paths.
 */
class FakeScimClient implements ScimClient
{
    /**
     * Remote store: connectionId => (remoteId => resource).
     *
     * @var array<string, array<string, array<string, mixed>>>
     */
    public array $remote = [];

    /**
     * Every operation received, in order — for asserting exact SCIM shapes.
     *
     * @var list<array<string, mixed>>
     */
    public array $requests = [];

    /**
     * Queued fault responses per connection (`*` = any); a value of 0 means a
     * transport error. Lets a test fail one connection while another succeeds.
     *
     * @var array<string, list<int>>
     */
    private array $faults = [];

    /**
     * Pre-seed a remote record so a create hits 409 (uniqueness) and can be
     * reconciled by externalId — or so a later update/delete has a target.
     *
     * @param  array<string, mixed>  $resource
     */
    public function seedRemote(string $connectionId, string $externalId, string $remoteId, array $resource = []): void
    {
        $this->remote[$connectionId][$remoteId] = ['id' => $remoteId, 'externalId' => $externalId] + $resource;
    }

    /** Delete a remote record out-of-band, so the next PATCH against it returns 404. */
    public function dropRemote(string $connectionId, string $remoteId): void
    {
        unset($this->remote[$connectionId][$remoteId]);
    }

    /** Make the next `$times` operations (on `$connectionId`, or any) fail with this HTTP status. */
    public function failWith(int $status, int $times = 1, ?string $connectionId = null): void
    {
        $key = $connectionId ?? '*';

        for ($i = 0; $i < $times; $i++) {
            $this->faults[$key][] = $status;
        }
    }

    /** Make the next `$times` operations fail at the transport layer (no response). */
    public function failTransport(int $times = 1, ?string $connectionId = null): void
    {
        $this->failWith(0, $times, $connectionId);
    }

    public function createUser(ProvisioningConnection $connection, array $resource): ScimResult
    {
        $this->requests[] = ['type' => 'create', 'connection' => $connection->id, 'resource' => $resource];

        if (($fault = $this->nextFault($connection->id)) !== null) {
            return $fault;
        }

        $externalId = is_string($resource['externalId'] ?? null) ? $resource['externalId'] : '';

        if ($externalId !== '' && $this->findRemoteId($connection->id, $externalId) !== null) {
            return ScimResult::http(409, ['schemas' => ['urn:ietf:params:scim:api:messages:2.0:Error'], 'status' => '409', 'scimType' => 'uniqueness']);
        }

        $remoteId = (string) Str::ulid();
        $stored = ['id' => $remoteId] + $resource;
        $this->remote[$connection->id][$remoteId] = $stored;

        return ScimResult::http(201, $stored);
    }

    public function patchUser(ProvisioningConnection $connection, string $remoteId, array $operations): ScimResult
    {
        $this->requests[] = ['type' => 'patch', 'connection' => $connection->id, 'remoteId' => $remoteId, 'operations' => $operations];

        if (($fault = $this->nextFault($connection->id)) !== null) {
            return $fault;
        }

        if (! isset($this->remote[$connection->id][$remoteId])) {
            return ScimResult::http(404);
        }

        $resource = $this->remote[$connection->id][$remoteId];

        foreach ($operations as $operation) {
            $path = $operation['path'] ?? null;
            if (is_string($path)) {
                $resource[$path] = $operation['value'] ?? null;
            }
        }

        $this->remote[$connection->id][$remoteId] = $resource;

        return ScimResult::http(200, $resource);
    }

    public function deleteUser(ProvisioningConnection $connection, string $remoteId): ScimResult
    {
        $this->requests[] = ['type' => 'delete', 'connection' => $connection->id, 'remoteId' => $remoteId];

        if (($fault = $this->nextFault($connection->id)) !== null) {
            return $fault;
        }

        if (! isset($this->remote[$connection->id][$remoteId])) {
            return ScimResult::http(404);
        }

        unset($this->remote[$connection->id][$remoteId]);

        return ScimResult::http(204);
    }

    public function findByExternalId(ProvisioningConnection $connection, string $externalId): ?string
    {
        $this->requests[] = ['type' => 'find', 'connection' => $connection->id, 'externalId' => $externalId];

        return $this->findRemoteId($connection->id, $externalId);
    }

    /**
     * All operations of a given type recorded so far.
     *
     * @return list<array<string, mixed>>
     */
    public function requestsOfType(string $type): array
    {
        return array_values(array_filter($this->requests, fn (array $request): bool => $request['type'] === $type));
    }

    private function findRemoteId(string $connectionId, string $externalId): ?string
    {
        foreach ($this->remote[$connectionId] ?? [] as $remoteId => $resource) {
            if (($resource['externalId'] ?? null) === $externalId) {
                return $remoteId;
            }
        }

        return null;
    }

    private function nextFault(string $connectionId): ?ScimResult
    {
        // A connection-specific fault takes precedence over an any-connection one.
        foreach ([$connectionId, '*'] as $key) {
            if (! empty($this->faults[$key])) {
                $status = array_shift($this->faults[$key]);

                return $status === 0
                    ? ScimResult::transportError()
                    : ScimResult::http($status, ['schemas' => ['urn:ietf:params:scim:api:messages:2.0:Error'], 'status' => (string) $status]);
            }
        }

        return null;
    }
}
