<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Exceptions\CannotCheckpointEmptyScope;
use Cbox\Id\Kernel\Audit\Models\AuditCheckpoint;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Audit\ValueObjects\ChainVerification;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Illuminate\Support\Facades\DB;

final class DatabaseAuditLog implements AuditLog
{
    private const SYSTEM_SCOPE = '__system__';

    private const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

    public function __construct(private readonly TokenSigner $signer) {}

    public function record(AuditEvent $event): AuditEntry
    {
        $scope = $this->scopeFor($event->organizationId);

        return DB::transaction(function () use ($event, $scope): AuditEntry {
            $last = $this->headEntry($scope, lock: true);

            if ($last === null) {
                $prevHash = self::GENESIS_HASH;
                $sequence = 1;
            } else {
                $prevHash = $last->hash;
                $sequence = $last->sequence + 1;
            }

            $entry = new AuditEntry;
            $entry->fill([
                'scope' => $scope,
                'organization_id' => $event->organizationId,
                'sequence' => $sequence,
                'actor_type' => $event->actorType,
                'actor_id' => $event->actorId,
                'action' => $event->action,
                'target_type' => $event->targetType,
                'target_id' => $event->targetId,
                'context' => $event->context,
                'ip' => $event->ip,
                'recorded_at' => now(),
            ]);
            $entry->prev_hash = $prevHash;
            $entry->hash = $this->computeHash($entry, $prevHash);
            $entry->save();

            return $entry;
        });
    }

    public function verifyChain(?string $organizationId = null, int $fromSequence = 1, ?int $toSequence = null): ChainVerification
    {
        $scope = $this->scopeFor($organizationId);
        $from = max(1, $fromSequence);

        $query = AuditEntry::query()
            ->where('scope', $scope)
            ->where('sequence', '>=', $from)
            ->orderBy('sequence');

        if ($toSequence !== null) {
            $query->where('sequence', '<=', $toSequence);
        }

        $entries = $query->get();

        $expectedSequence = $from;
        $prevHash = self::GENESIS_HASH;

        if ($from > 1) {
            $before = $this->entryAt($scope, $from - 1);
            $prevHash = $before === null ? self::GENESIS_HASH : $before->hash;
        }

        foreach ($entries as $entry) {
            if ($entry->sequence !== $expectedSequence) {
                return ChainVerification::broken($entry->sequence, 'sequence gap or reordering');
            }

            if (! hash_equals($prevHash, $entry->prev_hash)) {
                return ChainVerification::broken($entry->sequence, 'prev-hash linkage mismatch');
            }

            if (! hash_equals($entry->hash, $this->computeHash($entry, $entry->prev_hash))) {
                return ChainVerification::broken($entry->sequence, 'content hash mismatch (tampered)');
            }

            $prevHash = $entry->hash;
            $expectedSequence++;
        }

        return ChainVerification::valid($entries->count());
    }

    public function checkpoint(?string $organizationId = null): AuditCheckpoint
    {
        $scope = $this->scopeFor($organizationId);

        $head = $this->headEntry($scope, lock: false);

        if ($head === null) {
            throw CannotCheckpointEmptyScope::make($scope);
        }

        $signature = $this->signer->sign([
            'typ' => 'cbox-id.audit.checkpoint',
            'scope' => $scope,
            'up_to_sequence' => $head->sequence,
            'root_hash' => $head->hash,
            'iat' => now()->getTimestamp(),
        ]);

        $checkpoint = new AuditCheckpoint;
        $checkpoint->fill([
            'scope' => $scope,
            'organization_id' => $organizationId,
            'up_to_sequence' => $head->sequence,
            'root_hash' => $head->hash,
            'signature' => $signature,
        ]);
        $checkpoint->save();

        return $checkpoint;
    }

    private function headEntry(string $scope, bool $lock): ?AuditEntry
    {
        $query = AuditEntry::query()->where('scope', $scope)->orderByDesc('sequence');

        if ($lock) {
            $query->lockForUpdate();
        }

        return $query->first();
    }

    private function entryAt(string $scope, int $sequence): ?AuditEntry
    {
        return AuditEntry::query()
            ->where('scope', $scope)
            ->where('sequence', $sequence)
            ->first();
    }

    private function scopeFor(?string $organizationId): string
    {
        return $organizationId ?? self::SYSTEM_SCOPE;
    }

    private function computeHash(AuditEntry $entry, string $prevHash): string
    {
        return hash('sha256', $this->canonicalPayload($entry).$prevHash);
    }

    private function canonicalPayload(AuditEntry $entry): string
    {
        $payload = [
            'sequence' => $entry->sequence,
            'scope' => $entry->scope,
            'organization_id' => $entry->organization_id,
            'actor_type' => $entry->actor_type->value,
            'actor_id' => $entry->actor_id,
            'action' => $entry->action,
            'target_type' => $entry->target_type,
            'target_id' => $entry->target_id,
            'context' => $this->canonicalize($entry->context),
            'ip' => $entry->ip,
            'recorded_at' => $entry->recorded_at?->getTimestamp(),
        ];

        return json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * Deterministic, recursively key-sorted structure so the hash is stable.
     *
     * @param  array<array-key, mixed>  $data
     * @return array<array-key, mixed>
     */
    private function canonicalize(array $data): array
    {
        ksort($data);

        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = $this->canonicalize($value);
            }
        }

        return $data;
    }
}
