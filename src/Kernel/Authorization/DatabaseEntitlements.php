<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;
use Cbox\Id\Kernel\Authorization\Contracts\EntitlementWriter;
use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Cbox\Id\Kernel\Authorization\Models\Entitlement;
use Cbox\Id\Kernel\Authorization\Models\EntitlementChange;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementInput;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementValue;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Illuminate\Support\Facades\DB;

/**
 * Database-backed entitlement projection. Reads and writes the current state;
 * every write is versioned, appended to history, emitted as an event and audited.
 */
final class DatabaseEntitlements implements EntitlementReader, EntitlementWriter
{
    public function __construct(
        private readonly EventBus $events,
        private readonly AuditLog $audit,
    ) {}

    public function get(string $organizationId, string $key): ?EntitlementValue
    {
        $entitlement = $this->find($organizationId, $key);

        if ($entitlement === null || $this->isExpired($entitlement)) {
            return null;
        }

        return $this->toValue($entitlement);
    }

    public function all(string $organizationId): array
    {
        $result = [];

        foreach (Entitlement::query()->where('organization_id', $organizationId)->get() as $entitlement) {
            if ($this->isExpired($entitlement)) {
                continue;
            }

            $result[$entitlement->key] = $this->toValue($entitlement);
        }

        return $result;
    }

    public function set(
        string $organizationId,
        EntitlementInput $input,
        EntitlementSource $source,
        ?string $sourceRef = null,
    ): EntitlementValue {
        return DB::transaction(function () use ($organizationId, $input, $source, $sourceRef): EntitlementValue {
            $existing = $this->find($organizationId, $input->key);
            $version = ($existing === null ? 0 : $existing->version) + 1;

            $entitlement = Entitlement::query()->updateOrCreate(
                ['organization_id' => $organizationId, 'key' => $input->key],
                [
                    'value' => $input->value,
                    'mode' => $input->mode,
                    'source' => $source,
                    'source_ref' => $sourceRef,
                    'version' => $version,
                    'effective_at' => now(),
                ],
            );

            $this->history($organizationId, $input->key, $input->value, $source, $sourceRef, $version, 'set');
            $this->emitAndAudit($organizationId, $input->key, 'entitlement.updated', 'entitlement.set', [
                'value' => $input->value,
                'version' => $version,
                'source' => $source->value,
            ]);

            return $this->toValue($entitlement);
        });
    }

    public function revoke(string $organizationId, string $key, EntitlementSource $source): void
    {
        DB::transaction(function () use ($organizationId, $key, $source): void {
            $existing = $this->find($organizationId, $key);

            if ($existing === null) {
                return;
            }

            $version = $existing->version + 1;
            $existing->delete();

            $this->history($organizationId, $key, null, $source, null, $version, 'revoke');
            $this->emitAndAudit($organizationId, $key, 'entitlement.revoked', 'entitlement.revoked', [
                'version' => $version,
                'source' => $source->value,
            ]);
        });
    }

    public function reconcile(string $organizationId, array $authoritative, EntitlementSource $source): void
    {
        DB::transaction(function () use ($organizationId, $authoritative, $source): void {
            $desired = [];

            foreach ($authoritative as $input) {
                $desired[$input->key] = true;
                $this->set($organizationId, $input, $source);
            }

            foreach (Entitlement::query()->where('organization_id', $organizationId)->get() as $current) {
                if (! isset($desired[$current->key])) {
                    $this->revoke($organizationId, $current->key, $source);
                }
            }
        });
    }

    private function find(string $organizationId, string $key): ?Entitlement
    {
        return Entitlement::query()
            ->where('organization_id', $organizationId)
            ->where('key', $key)
            ->first();
    }

    private function isExpired(Entitlement $entitlement): bool
    {
        return $entitlement->expires_at !== null && $entitlement->expires_at->isPast();
    }

    private function toValue(Entitlement $entitlement): EntitlementValue
    {
        return new EntitlementValue(
            $entitlement->key,
            $entitlement->value,
            $entitlement->mode,
            $entitlement->source,
            $entitlement->version,
        );
    }

    /**
     * @param  array<string, mixed>|null  $value
     */
    private function history(
        string $organizationId,
        string $key,
        ?array $value,
        EntitlementSource $source,
        ?string $sourceRef,
        int $version,
        string $change,
    ): void {
        $record = new EntitlementChange;
        $record->fill([
            'organization_id' => $organizationId,
            'key' => $key,
            'value' => $value,
            'source' => $source,
            'source_ref' => $sourceRef,
            'version' => $version,
            'change' => $change,
            'recorded_at' => now(),
        ]);
        $record->save();
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private function emitAndAudit(
        string $organizationId,
        string $key,
        string $eventType,
        string $auditAction,
        array $payload,
    ): void {
        $this->events->emit(new DomainEvent($eventType, ['key' => $key] + $payload, $organizationId));

        $this->audit->record(new AuditEvent(
            action: $auditAction,
            actorType: ActorType::System,
            organizationId: $organizationId,
            targetType: 'entitlement',
            targetId: $key,
            context: $payload,
        ));
    }
}
