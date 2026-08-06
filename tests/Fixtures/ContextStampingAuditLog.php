<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Models\AuditCheckpoint;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Audit\ValueObjects\ChainVerification;

/**
 * A minimal host-style {@see AuditLog} decorator used to prove the streaming
 * decorator COMPOSES: it stamps a context key onto every event before delegating,
 * exactly as the app's impersonation-attribution decorator does. When bound OUTSIDE
 * the streaming decorator, the stamped key must flow through to the SIEM.
 */
final class ContextStampingAuditLog implements AuditLog
{
    /**
     * @param  array<string, scalar|null>  $stamp
     */
    public function __construct(
        private readonly AuditLog $inner,
        private readonly array $stamp,
    ) {}

    public function record(AuditEvent $event): AuditEntry
    {
        return $this->inner->record(new AuditEvent(
            action: $event->action,
            actorType: $event->actorType,
            actorId: $event->actorId,
            organizationId: $event->organizationId,
            targetType: $event->targetType,
            targetId: $event->targetId,
            context: array_merge($event->context, $this->stamp),
            ip: $event->ip,
        ));
    }

    public function verifyChain(?string $organizationId = null, int $fromSequence = 1, ?int $toSequence = null): ChainVerification
    {
        return $this->inner->verifyChain($organizationId, $fromSequence, $toSequence);
    }

    public function checkpoint(?string $organizationId = null): AuditCheckpoint
    {
        return $this->inner->checkpoint($organizationId);
    }
}
