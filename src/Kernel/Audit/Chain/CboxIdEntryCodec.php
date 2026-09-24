<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\Chain;

use Cbox\AuditChain\Contracts\EntryCodec;
use Cbox\AuditChain\Models\ChainEntry;
use Cbox\Id\Kernel\Audit\DatabaseAuditLog;

/**
 * The canonical form every `audit_logs` row has been hashed with since the chain was
 * introduced — reproduced byte for byte, so every existing chain keeps verifying and
 * every new entry extends it with the hash the pre-extraction {@see DatabaseAuditLog}
 * would have computed.
 *
 * FROZEN. It is NOT the package's `audit-chain/v1` form, and must not become it: the
 * fields are in a fixed order (not sorted), the partition is named `environment_id`,
 * `organization_id` is hashed, and the context is sorted with `ksort()`'s DEFAULT flags.
 * Changing any of that re-chains every trail in every deployment, and after the first
 * signed checkpoint that is indistinguishable from tampering. tests/Feature/Kernel/Audit/
 * GoldenVectors pins it against rows the pre-extraction implementation wrote.
 */
class CboxIdEntryCodec implements EntryCodec
{
    public const VERSION = 'cbox-id/v1';

    public function version(): string
    {
        return self::VERSION;
    }

    /**
     * `organization_id` is hashed, and it is the one host column an append may write.
     */
    public function extraColumns(): array
    {
        return ['organization_id'];
    }

    public function canonicalize(ChainEntry $entry): string
    {
        // Read RAW, exactly as the pre-extraction code read `$entry->environment_id` and
        // `$entry->organization_id` — no normalisation, so no row can hash differently.
        $payload = [
            'sequence' => $entry->sequence,
            // The chain is defined per (environment, scope), so the environment must be
            // INSIDE the hash — otherwise a row can be moved between environments with a
            // plain UPDATE and verifyChain() still reports it intact.
            'environment_id' => $entry->getAttribute($entry->chainPartitionColumn()),
            'scope' => $entry->scope,
            'organization_id' => $entry->getAttribute('organization_id'),
            'actor_type' => $entry->actorTypeValue(),
            'actor_id' => $entry->actor_id,
            'action' => $entry->action,
            'target_type' => $entry->target_type,
            'target_id' => $entry->target_id,
            'context' => $this->canonicalizeContext($entry->context),
            'ip' => $entry->ip,
            'recorded_at' => $entry->recorded_at?->getTimestamp(),
        ];

        return json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * Deterministic, recursively key-sorted structure so the hash is stable.
     *
     * `ksort()` with its DEFAULT flags, exactly as the rows were written — not the
     * package's byte-order sort. The two differ for mixed numeric/string keys.
     *
     * @param  array<array-key, mixed>  $data
     * @return array<array-key, mixed>
     */
    private function canonicalizeContext(array $data): array
    {
        ksort($data);

        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = $this->canonicalizeContext($value);
            }
        }

        return $data;
    }
}
