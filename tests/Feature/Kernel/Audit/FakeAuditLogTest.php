<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;

it('fakes the audit log and asserts recorded events', function (): void {
    $audit = $this->fakeAudit();

    app(AuditLog::class)->record(AuditEvent::forUser('connection.activated', 'user_1', 'org_a'));

    $audit->assertRecorded('connection.activated');
    $audit->assertRecorded('connection.activated', fn (AuditEvent $event): bool => $event->organizationId === 'org_a');
    $audit->assertNotRecorded('connection.deleted');
    $audit->assertRecordedCount(1);
});

it('asserts that nothing was recorded', function (): void {
    $audit = $this->fakeAudit();

    $audit->assertNothingRecorded();
});
