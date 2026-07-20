<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\Testing;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Models\AuditCheckpoint;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Audit\ValueObjects\ChainVerification;
use Closure;
use PHPUnit\Framework\Assert;

/**
 * In-memory {@see AuditLog} for tests: records events without touching the
 * database and exposes assertions, in the spirit of Laravel's `Event::fake()`.
 */
class FakeAuditLog implements AuditLog
{
    /**
     * @var list<AuditEvent>
     */
    public array $recorded = [];

    public function record(AuditEvent $event): AuditEntry
    {
        $this->recorded[] = $event;

        return (new AuditEntry)->fill([
            'scope' => $event->organizationId ?? '__system__',
            'organization_id' => $event->organizationId,
            'action' => $event->action,
        ]);
    }

    public function verifyChain(?string $organizationId = null, int $fromSequence = 1, ?int $toSequence = null): ChainVerification
    {
        return ChainVerification::valid(count($this->recorded));
    }

    public function checkpoint(?string $organizationId = null): AuditCheckpoint
    {
        return (new AuditCheckpoint)->fill([
            'scope' => $organizationId ?? '__system__',
            'organization_id' => $organizationId,
            'up_to_sequence' => count($this->recorded),
            'root_hash' => str_repeat('0', 64),
            'signature' => 'fake',
        ]);
    }

    /**
     * @param  (Closure(AuditEvent): bool)|null  $callback
     */
    public function assertRecorded(string $action, ?Closure $callback = null): void
    {
        $matches = array_filter(
            $this->recorded,
            fn (AuditEvent $event): bool => $event->action === $action
                && ($callback === null || $callback($event)),
        );

        Assert::assertNotEmpty($matches, "Expected an audit event [{$action}] to be recorded, but none was.");
    }

    public function assertNotRecorded(string $action): void
    {
        $matches = array_filter($this->recorded, fn (AuditEvent $event): bool => $event->action === $action);

        Assert::assertEmpty($matches, "Did not expect an audit event [{$action}] to be recorded.");
    }

    public function assertNothingRecorded(): void
    {
        Assert::assertEmpty($this->recorded, 'Expected no audit events to be recorded.');
    }

    public function assertRecordedCount(int $count): void
    {
        Assert::assertCount($count, $this->recorded);
    }
}
