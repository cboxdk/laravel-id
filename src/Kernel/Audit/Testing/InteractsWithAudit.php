<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\Testing;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;

/**
 * Swap the audit log for an assertable fake, `Event::fake()`-style:
 *
 *     $audit = $this->fakeAudit();
 *     // ... exercise code ...
 *     $audit->assertRecorded('connection.activated');
 */
trait InteractsWithAudit
{
    protected function fakeAudit(): FakeAuditLog
    {
        $fake = new FakeAuditLog;

        app()->instance(AuditLog::class, $fake);

        return $fake;
    }
}
