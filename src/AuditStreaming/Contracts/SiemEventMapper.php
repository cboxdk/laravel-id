<?php

declare(strict_types=1);

namespace Cbox\Id\AuditStreaming\Contracts;

use Cbox\Id\AuditStreaming\Support\DefaultSiemEventMapper;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Siem\ValueObjects\SiemEvent;

/**
 * Maps a persisted, hash-chained {@see AuditEntry} onto the transport-neutral
 * {@see SiemEvent} the SIEM formatters consume.
 *
 * The mapping is a seam, not a hardcode: bind your own implementation through the
 * container to refine how actions become categories/outcomes/severities for your
 * domain's action vocabulary. The default ({@see DefaultSiemEventMapper})
 * is deliberately conservative and documents its rules.
 *
 * Two invariants every implementation MUST preserve, because customers rely on
 * them to verify and dedup:
 *  - `SiemEvent::$id` is the entry's chain `hash` (a stable idempotency key);
 *  - `SiemEvent::$context` carries `sequence`, `hash`, `prev_hash` and
 *    `organization_id`, so the receiver can check chain continuity and detect
 *    gaps, reordering or replay.
 */
interface SiemEventMapper
{
    public function toSiemEvent(AuditEntry $entry): SiemEvent;
}
