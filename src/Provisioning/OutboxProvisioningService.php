<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning;

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Provisioning\Contracts\ProvisioningConnections;
use Cbox\Id\Provisioning\Contracts\ProvisioningService;
use Cbox\Id\Provisioning\Contracts\ScimClient;
use Cbox\Id\Provisioning\Enums\ConnectionStatus;
use Cbox\Id\Provisioning\Enums\DeprovisionPolicy;
use Cbox\Id\Provisioning\Enums\OperationStatus;
use Cbox\Id\Provisioning\Enums\OperationType;
use Cbox\Id\Provisioning\Enums\ResourceState;
use Cbox\Id\Provisioning\Models\ProvisionedResource;
use Cbox\Id\Provisioning\Models\ProvisioningConnection;
use Cbox\Id\Provisioning\Models\ProvisioningOperation;
use Cbox\Id\Provisioning\Support\AttributeMapping;
use Cbox\Id\Provisioning\Support\ConnectionCircuitBreaker;
use Cbox\Id\Provisioning\ValueObjects\ScimResult;
use Cbox\Id\Scim\ScimSchema;

/**
 * The default {@see ProvisioningService}: an outbox translator + stateful drain.
 *
 * Translation ({@see enqueueForEvent()}) maps a domain event to one
 * {@see OperationType} and writes a durable {@see ProvisioningOperation} per
 * in-scope connection — off the caller's hot path, deny-by-default (no connection
 * ⇒ nothing enqueued). Delivery ({@see drainConnection()}) is where SCIM's
 * statefulness lives: the {@see ProvisionedResource} for a user tells us whether
 * to POST (create, capturing the remote id) or PATCH `/Users/{remote_id}`
 * (update), and it is reconciled on a 409 (match the existing remote by
 * `externalId`) or a 404 (recreate).
 */
final class OutboxProvisioningService implements ProvisioningService
{
    /**
     * Domain event → SCIM operation. An event outside this map enqueues nothing.
     *
     * @var array<string, OperationType>
     */
    private const EVENT_MAP = [
        'user.created' => OperationType::Upsert,
        'user.updated' => OperationType::Upsert,
        'user.reactivated' => OperationType::Reactivate,
        'user.deactivated' => OperationType::Deactivate,
        'organization.member_added' => OperationType::Upsert,
        'organization.member_role_changed' => OperationType::Upsert,
        'organization.member_removed' => OperationType::Deprovision,
    ];

    public function __construct(
        private readonly ProvisioningConnections $connections,
        private readonly ScimClient $client,
        private readonly Subjects $subjects,
        private readonly Memberships $memberships,
        private readonly ConnectionCircuitBreaker $breaker,
    ) {}

    public function enqueueForEvent(string $eventType, array $payload, ?string $organizationId): int
    {
        $type = self::EVENT_MAP[$eventType] ?? null;

        if ($type === null) {
            return 0;
        }

        $userId = $payload['user_id'] ?? null;

        if (! is_string($userId) || $userId === '') {
            return 0;
        }

        // Deny-by-default: only connections in the CURRENT environment (an env-B
        // connection is invisible here via the hard scope). A deprovision targets
        // only connections the user has genuinely LEFT — never one that still covers
        // them through another org or environment-wide — so a member-removal cannot
        // deactivate/DELETE a still-entitled user. Every other change targets the
        // in-scope set.
        $connections = $type === OperationType::Deprovision
            ? $this->connections->leftScopeFor($userId, $organizationId)
            : $this->connections->inScopeFor($userId, $organizationId);

        if ($connections->isEmpty()) {
            return 0;
        }

        $source = $this->snapshot($userId);
        $enqueued = 0;

        foreach ($connections as $connection) {
            $this->enqueue($connection->id, $userId, $type, $source);
            $enqueued++;
        }

        return $enqueued;
    }

    public function drainConnection(string $connectionId): int
    {
        $connection = ProvisioningConnection::query()->whereKey($connectionId)->first();

        if ($connection === null || $connection->status !== ConnectionStatus::Active) {
            return 0;
        }

        // Circuit breaker: a downstream app that just tripped is left alone until
        // its cooldown elapses — its pending rows stay pending, other connections
        // are untouched.
        if (! $this->breaker->shouldAttempt($connection)) {
            return 0;
        }

        $operations = ProvisioningOperation::query()
            ->where('connection_id', $connectionId)
            ->whereIn('status', [OperationStatus::Pending->value, OperationStatus::Failed->value])
            ->where(function ($query): void {
                $query->whereNull('next_attempt_at')->orWhere('next_attempt_at', '<=', now());
            })
            ->orderBy('id')
            ->limit($this->batchLimit())
            ->get();

        $delivered = 0;

        foreach ($operations as $operation) {
            if ($this->deliver($connection, $operation)) {
                $delivered++;
            }

            // A failure may have just opened the breaker mid-drain (which stamps
            // circuit_opened_at); if so, stop and leave the remaining operations
            // pending — the cooldown gate is re-checked when the next run starts.
            if ($connection->circuit_opened_at !== null) {
                break;
            }
        }

        return $delivered;
    }

    public function reconcileConnection(string $connectionId): int
    {
        $connection = ProvisioningConnection::query()->whereKey($connectionId)->first();

        if ($connection === null || $connection->status !== ConnectionStatus::Active) {
            return 0;
        }

        $enqueued = 0;

        foreach ($this->inScopeSubjectIds($connection) as $userId) {
            $this->enqueue($connection->id, $userId, OperationType::Upsert, $this->snapshot($userId));
            $enqueued++;
        }

        return $enqueued;
    }

    /**
     * Deliver one operation, statefully. Returns true when it reached a delivered
     * (terminal-success) state.
     */
    private function deliver(ProvisioningConnection $connection, ProvisioningOperation $operation): bool
    {
        $operation->attempt += 1;

        $resource = $this->resourceFor($connection->id, $operation->user_id);
        $source = $operation->payload;

        $result = match ($operation->type) {
            OperationType::Upsert,
            OperationType::Reactivate => $this->upsert($connection, $operation, $resource, $source),
            OperationType::Deactivate => $this->deactivate($connection, $resource),
            OperationType::Deprovision => $this->deprovision($connection, $resource),
        };

        return $this->finalize($connection, $operation, $result);
    }

    /**
     * Create-or-update. With a captured remote id we PATCH it (recreating on a
     * 404); without one we POST (reconciling a 409 back to the existing record).
     *
     * @param  array<string, mixed>  $source
     */
    private function upsert(
        ProvisioningConnection $connection,
        ProvisioningOperation $operation,
        ?ProvisionedResource $resource,
        array $source,
    ): ScimResult {
        $externalId = $operation->user_id;
        $mapping = $connection->attribute_mapping;

        if ($resource !== null && is_string($resource->remote_id) && $resource->remote_id !== '') {
            $result = $this->client->patchUser(
                $connection,
                $resource->remote_id,
                AttributeMapping::patchOperations($mapping, $source, active: true),
            );

            // The remote record was deleted out from under us — recreate it.
            if ($result->notFound()) {
                return $this->createAndCapture($connection, $operation->user_id, $externalId, $source);
            }

            if ($result->successful()) {
                $this->writeResource($connection->id, $operation->user_id, $externalId, $resource->remote_id, ResourceState::Active);
            }

            return $result;
        }

        return $this->createAndCapture($connection, $operation->user_id, $externalId, $source);
    }

    /**
     * POST /Users, capturing the assigned remote id. On a 409 uniqueness conflict
     * (the user already exists remotely — a prior partial sync, or created
     * out-of-band) locate the record by `externalId` and PATCH it, so we reconcile
     * instead of duplicating.
     *
     * @param  array<string, mixed>  $source
     */
    private function createAndCapture(
        ProvisioningConnection $connection,
        string $userId,
        string $externalId,
        array $source,
    ): ScimResult {
        $mapping = $connection->attribute_mapping;
        $result = $this->client->createUser(
            $connection,
            AttributeMapping::resource($externalId, $mapping, $source, active: true),
        );

        if ($result->successful()) {
            $this->writeResource($connection->id, $userId, $externalId, $result->remoteId(), ResourceState::Active);

            return $result;
        }

        if ($result->conflict()) {
            $remoteId = $this->client->findByExternalId($connection, $externalId);

            if ($remoteId !== null) {
                $patch = $this->client->patchUser(
                    $connection,
                    $remoteId,
                    AttributeMapping::patchOperations($mapping, $source, active: true),
                );

                if ($patch->successful()) {
                    $this->writeResource($connection->id, $userId, $externalId, $remoteId, ResourceState::Active);
                }

                return $patch;
            }
        }

        return $result;
    }

    private function deactivate(ProvisioningConnection $connection, ?ProvisionedResource $resource): ScimResult
    {
        if ($resource === null || ! is_string($resource->remote_id) || $resource->remote_id === '') {
            // Never provisioned here ⇒ nothing to deactivate; a no-op success.
            return ScimResult::http(204);
        }

        $result = $this->client->patchUser($connection, $resource->remote_id, [ScimSchema::setActive(false)]);

        if ($result->successful() || $result->notFound()) {
            $this->markResourceState($resource, ResourceState::Deactivated);

            return $result->notFound() ? ScimResult::http(204) : $result;
        }

        return $result;
    }

    private function deprovision(ProvisioningConnection $connection, ?ProvisionedResource $resource): ScimResult
    {
        if ($resource === null || ! is_string($resource->remote_id) || $resource->remote_id === '') {
            return ScimResult::http(204);
        }

        if ($connection->deprovision_policy === DeprovisionPolicy::Delete) {
            $result = $this->client->deleteUser($connection, $resource->remote_id);

            if ($result->successful() || $result->notFound()) {
                // Forget the remote id so a later re-add cleanly re-creates.
                $resource->remote_id = null;
                $this->markResourceState($resource, ResourceState::Deprovisioned);

                return $result->notFound() ? ScimResult::http(204) : $result;
            }

            return $result;
        }

        return $this->deactivate($connection, $resource);
    }

    /**
     * Classify the outcome and stage it on the operation + connection health.
     */
    private function finalize(ProvisioningConnection $connection, ProvisioningOperation $operation, ScimResult $result): bool
    {
        $operation->response_code = $result->transport ? null : $result->status;

        if ($result->successful()) {
            $operation->status = OperationStatus::Delivered;
            $operation->delivered_at = now();
            $operation->next_attempt_at = null;
            $operation->last_error = null;
            $this->breaker->recordSuccess($connection);
            $delivered = true;
        } elseif ($result->transient()) {
            // Destination down/rate-limited/unreachable → retry with backoff, and
            // count it against the breaker (repeated failures open it).
            $this->scheduleRetry($operation, $result->errorDetail());
            $this->breaker->recordFailure($connection, $result->errorDetail());
            $delivered = false;
        } else {
            // A permanent client error (a 4xx we don't specially handle) will not
            // fix itself — dead-letter it now, but do NOT trip the breaker (the
            // destination is healthy; the request was rejected).
            $operation->status = OperationStatus::Exhausted;
            $operation->next_attempt_at = null;
            $operation->last_error = $result->errorDetail();
            $delivered = false;
        }

        $operation->save();
        $connection->save();

        return $delivered;
    }

    private function scheduleRetry(ProvisioningOperation $operation, string $error): void
    {
        $operation->last_error = $error;

        if ($operation->attempt >= $this->maxAttempts()) {
            $operation->status = OperationStatus::Exhausted;
            $operation->next_attempt_at = null;

            return;
        }

        $operation->status = OperationStatus::Failed;
        // Bounded exponential backoff (cap 60 min) plus jitter, so a fleet of
        // stuck operations does not retry in lockstep and thundering-herd the
        // downstream app when it recovers.
        $backoff = min(60, 2 ** $operation->attempt);
        $operation->next_attempt_at = now()->addMinutes($backoff)->addSeconds(random_int(0, 30));
    }

    /**
     * Snapshot the platform attributes to provision, so an operation is
     * self-contained at delivery time.
     *
     * @return array<string, mixed>
     */
    private function snapshot(string $userId): array
    {
        $subject = $this->subjects->find($userId);

        if ($subject === null) {
            return [];
        }

        return array_filter([
            'email' => $subject->email,
            'name' => $subject->name,
        ], fn ($value): bool => $value !== null);
    }

    /**
     * @param  array<string, mixed>  $source
     */
    private function enqueue(string $connectionId, string $userId, OperationType $type, array $source): void
    {
        $operation = new ProvisioningOperation;
        $operation->fill([
            'connection_id' => $connectionId,
            'user_id' => $userId,
            'type' => $type,
            'payload' => $source,
            'status' => OperationStatus::Pending,
            'attempt' => 0,
        ]);
        $operation->save();
    }

    private function resourceFor(string $connectionId, string $userId): ?ProvisionedResource
    {
        return ProvisionedResource::query()
            ->where('connection_id', $connectionId)
            ->where('user_id', $userId)
            ->first();
    }

    private function writeResource(string $connectionId, string $userId, string $externalId, ?string $remoteId, ResourceState $state): void
    {
        $resource = $this->resourceFor($connectionId, $userId) ?? new ProvisionedResource;
        $resource->fill([
            'connection_id' => $connectionId,
            'user_id' => $userId,
            'external_id' => $externalId,
            'remote_id' => $remoteId,
            'state' => $state,
            'last_synced_at' => now(),
        ]);
        $resource->save();
    }

    private function markResourceState(ProvisionedResource $resource, ResourceState $state): void
    {
        $resource->state = $state;
        $resource->last_synced_at = now();
        $resource->save();
    }

    /**
     * The platform user ids in scope for a full reconcile: every environment user
     * for an environment-wide connection, or the members of its organizations.
     *
     * @return list<string>
     */
    private function inScopeSubjectIds(ProvisioningConnection $connection): array
    {
        $ids = [];

        if ($connection->isEnvironmentWide()) {
            $model = $this->userModel();
            $keyName = (new $model)->getKeyName();

            foreach ($model::query()->pluck($keyName) as $userId) {
                if (is_string($userId)) {
                    $ids[$userId] = true;
                }
            }

            return array_keys($ids);
        }

        foreach ($connection->scopeOrganizationIds() as $organizationId) {
            foreach ($this->memberships->forOrganization($organizationId) as $membership) {
                $userId = $membership->getAttribute('user_id');

                if (is_string($userId)) {
                    $ids[$userId] = true;
                }
            }
        }

        return array_keys($ids);
    }

    /**
     * @return class-string<User>
     */
    private function userModel(): string
    {
        $configured = config('cbox-id.models.user');

        return is_string($configured) && is_a($configured, User::class, true) ? $configured : User::class;
    }

    private function batchLimit(): int
    {
        $configured = config('cbox-id.provisioning.batch_limit', 50);

        return max(1, is_numeric($configured) ? (int) $configured : 50);
    }

    private function maxAttempts(): int
    {
        $configured = config('cbox-id.provisioning.max_attempts', 12);

        return max(1, is_numeric($configured) ? (int) $configured : 12);
    }
}
